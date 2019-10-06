/*
 * SO2, Tema 2, Driver UART
 * Ghita Bogdan, 343C4
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <asm/io.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/kfifo.h>

#include "uart16550.h"

MODULE_AUTHOR("Ghita Bogdan");
MODULE_DESCRIPTION("Device driver for serial port UART16550");
MODULE_LICENSE("GPL");

static int major = 42;
static int option = OPTION_BOTH;

module_param(major, int, 0444);
MODULE_PARM_DESC(major, "Major of the device");
module_param(option, int, 0444);
MODULE_PARM_DESC(option, "Ports that will be registerd. 1 (OPTION_COM1), "
	"2 (OPTION_COM2), 3 (OPTION_BOTH)");

#define LOG_LEVEL       KERN_DEBUG
#define MODULE_NAME     "uart16550"

#define TRUE  1
#define FALSE 0

#define COM1 0
#define COM2 1

#define COM1_BASEPORT 0x3f8
#define COM2_BASEPORT 0x2f8

#define UART_THB  0
#define UART_RB   0
#define UART_IER  1
#define UART_IIR  2
#define UART_LCR  3
#define UART_DLLB 0

#define THREI 1
#define RDAI  2

#define IRQ_COM1 4
#define IRQ_COM2 3

#define BUFFER_SIZE 1024

struct device_data {
	struct cdev cdev;
	atomic_t file_access;
	int baseport;
	atomic_t read_buff_len;
	atomic_t write_buff_len;
	wait_queue_head_t wq_data_ready;
	wait_queue_head_t wq_write_ready;
	DECLARE_KFIFO(read_buffer, u8, BUFFER_SIZE);
	DECLARE_KFIFO(write_buffer, u8, BUFFER_SIZE);
};

static int uart_open(struct inode *inode, struct file *file);
static int uart_close(struct inode *inode, struct file *file);
static int uart_read(struct file *file, char *user_buffer, size_t size,
	loff_t *offset);
static int uart_write(struct file *file, const char *user_buffer, size_t size,
	loff_t *offset);
static long uart_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

static int device_baseport[MAX_NUMBER_DEVICES] = {COM1_BASEPORT, COM2_BASEPORT};
static int device_registered[MAX_NUMBER_DEVICES] = {FALSE, FALSE};
static struct device_data devs[MAX_NUMBER_DEVICES];
static const struct file_operations uart_fops = {
	.owner          = THIS_MODULE,
	.open           = uart_open,
	.read           = uart_read,
	.write          = uart_write,
	.release        = uart_close,
	.unlocked_ioctl = uart_ioctl
};

static void set_bits(int port_addr, u8 bits)
{
	u8 reg_val, new_val, mask;

	mask = bits;
	reg_val = inb(port_addr);
	new_val = reg_val | mask;
	outb(new_val, port_addr);
}

static void reset_bits(int port_addr, u8 bits)
{
	u8 reg_val, new_val, mask;

	mask = ~bits;
	reg_val = inb(port_addr);
	new_val = reg_val & mask;
	outb(new_val, port_addr);
}

static void init_device_data(struct device_data *data, int baseport)
{
	atomic_set(&data->file_access, 1);
	data->baseport = baseport;

	INIT_KFIFO(data->read_buffer);
	INIT_KFIFO(data->write_buffer);

	atomic_set(&data->read_buff_len, 0);
	atomic_set(&data->write_buff_len, 0);
	init_waitqueue_head(&data->wq_data_ready);
	init_waitqueue_head(&data->wq_write_ready);
}

static void clean_device_data(struct device_data *data)
{
}

static void init_uart(int baseport)
{
	/* Enable interrupts (RDAI, Receiver Line Status Interrupt) */
	set_bits(baseport + UART_IER, 0x05);
}

static void set_line_parameters(int baseport,
	struct uart16550_line_info line_info)
{
	reset_bits(baseport + UART_LCR, 63);
	set_bits(baseport + UART_LCR, line_info.len);
	set_bits(baseport + UART_LCR, line_info.stop);
	set_bits(baseport + UART_LCR, line_info.par);

	/* Set DLAB */
	set_bits(baseport + UART_LCR, 128);
	/* Se baud rate */
	outb(line_info.baud, baseport + UART_DLLB);
	/* Reset DLAB */
	reset_bits(baseport + UART_LCR, 128);
}

static void handle_data_ready_interrupt(struct device_data *data)
{
	u8 reg_val;
	unsigned int bytes_copied;

	printk(LOG_LEVEL "%s: [handle_data_ready_interrupt]\n", MODULE_NAME);

	if (kfifo_is_full(&data->read_buffer)) {
		printk(LOG_LEVEL "%s: [handle_data_ready_interrupt] read_buffer "
			"is full. Disabling RDAI\n", MODULE_NAME);
		/* Diasble RDAI */
		reset_bits(data->baseport + UART_IER, 0x01);
		return;
	}

	/* Read data from device and save it to read_buffer */
	reg_val = inb(data->baseport + UART_RB);
	bytes_copied = kfifo_in(&data->read_buffer, &reg_val, 1);
	if (bytes_copied == 0)
		return;

	/* Increment buff_len and notify read handler */
	atomic_inc(&data->read_buff_len);
	wake_up_interruptible(&data->wq_data_ready);
}

static void handle_write_ready_interrupt(struct device_data *data)
{
	u8 reg_val;
	unsigned int bytes_copied;

	printk(LOG_LEVEL "%s: [handle_write_ready_interrupt]\n", MODULE_NAME);

	if (kfifo_is_empty(&data->write_buffer)) {
		printk(LOG_LEVEL "%s: [handle_write_ready_interrupt] write_buffer is "
			"empty. Disabling THREI\n", MODULE_NAME);
		/* Diasble THREI */
		reset_bits(data->baseport + UART_IER, 0x02);
		return;
	}

	/* Remove data from write_buffer and write it to device */
	bytes_copied = kfifo_out(&data->write_buffer, &reg_val, 1);
	if (bytes_copied == 0)
		return;
	outb(reg_val, data->baseport + UART_THB);

	/* Decrement write_buff_len and notify write handler */
	atomic_dec(&data->write_buff_len);
	wake_up_interruptible(&data->wq_write_ready);
}

irqreturn_t interrupt_handler(int irq_no, void *dev_id)
{
	u8 reg_val;
	int interrupt_pending, interrupt_status;
	struct device_data *data = (struct device_data *) dev_id;

	/* Read IIR */
	reg_val = inb(data->baseport + UART_IIR);
	interrupt_pending = !(reg_val & 0x01);
	interrupt_status = (reg_val >> 1) & 0x03;

	if (irq_no == IRQ_COM1) {
		printk(LOG_LEVEL "%s: [interrupt_handler][COM1] reg_val=%d, "
			"interrupt_pending=%d, interrupt_status=%d\n",
			MODULE_NAME, reg_val, interrupt_pending,
			interrupt_status);
	} else /*if(irq_no == IRQ_COM2)*/{
		printk(LOG_LEVEL "%s: [interrupt_handler][COM2] reg_val=%d, "
			"interrupt_pending=%d, interrupt_status=%d\n",
			MODULE_NAME, reg_val, interrupt_pending,
			interrupt_status);
	}

	if (!interrupt_pending)
		return IRQ_HANDLED;

	if (interrupt_status == RDAI) {
		handle_data_ready_interrupt(data);
		return IRQ_HANDLED;
	}
	if (interrupt_status == THREI) {
		handle_write_ready_interrupt(data);
		return IRQ_HANDLED;
	}

	return IRQ_NONE;
}

static int uart_open(struct inode *inode, struct file *file)
{
	struct device_data *data;

	printk(LOG_LEVEL "%s: [uart_open]\n", MODULE_NAME);

	data = container_of(inode->i_cdev, struct device_data, cdev);

	if (atomic_cmpxchg(&data->file_access, 1, 0) != 1)
		return -EBUSY;

	file->private_data = data;

	return 0;
}

static int uart_close(struct inode *inode, struct file *file)
{
	struct device_data *data;

	printk(LOG_LEVEL "%s: [uart_close]\n", MODULE_NAME);

	data = (struct device_data *)file->private_data;

	atomic_set(&data->file_access, 1);

	return 0;
}

static int uart_read(struct file *file, char *user_buffer, size_t size,
	loff_t *offset)
{
	int err;
	unsigned int bytes_copied;
	int read_cnt;
	struct device_data *data;

	printk(LOG_LEVEL "%s: [uart_read]\n", MODULE_NAME);

	data = (struct device_data *)file->private_data;

	/* Check if there is data to read and wait otherwise */
	wait_event_interruptible(data->wq_data_ready,
		atomic_read(&data->read_buff_len) > 0);

	printk(LOG_LEVEL "%s: [uart_read] Copying data from read_buffer",
		MODULE_NAME);
	/* Copy data from read_buffer */
	read_cnt = 0;
	while (read_cnt < size && !kfifo_is_empty(&data->read_buffer)) {
		err = kfifo_to_user(&data->read_buffer, user_buffer + read_cnt,
			1, &bytes_copied);
		if (err)
			return err;
		if (bytes_copied == 1) {
			read_cnt += 1;
			atomic_dec(&data->read_buff_len);
		}
	}

	/* Enable RDAI */
	set_bits(data->baseport + UART_IER, 0x01);

	return read_cnt;
}

static int uart_write(struct file *file, const char *user_buffer, size_t size,
	loff_t *offset)
{
	int err;
	unsigned int bytes_copied;
	int write_cnt, buff_size;
	struct device_data *data;

	printk(LOG_LEVEL "%s: [uart_write]\n", MODULE_NAME);

	data = (struct device_data *)file->private_data;

	/* Check if you can write and wait otherwise */
	buff_size = kfifo_size(&data->write_buffer);
	wait_event_interruptible(data->wq_write_ready,
		atomic_read(&data->write_buff_len) < buff_size);

	printk(LOG_LEVEL "%s: [uart_write] Copying data to write_buffer",
		MODULE_NAME);
	/* Copy data to write_buffer */
	write_cnt = 0;
	while (write_cnt < size && !kfifo_is_full(&data->write_buffer)) {
		err = kfifo_from_user(&data->write_buffer,
			user_buffer + write_cnt, 1, &bytes_copied);
		if (err)
			return err;
		if (bytes_copied == 1) {
			write_cnt += 1;
			atomic_inc(&data->write_buff_len);
		}
	}

	/* Enable THREI */
	set_bits(data->baseport + UART_IER, 0x02);

	return write_cnt;
}

static long uart_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct device_data *data;
	struct uart16550_line_info line_info;

	printk(LOG_LEVEL "%s: [uart_ioctl] cmd=%d\n", MODULE_NAME, cmd);

	data = (struct device_data *) file->private_data;

	switch (cmd) {
	case UART16550_IOCTL_SET_LINE:
		if (copy_from_user(&line_info, (void __user *)arg,
			sizeof(struct uart16550_line_info))) {
			printk(LOG_LEVEL "%s: [uart_ioctl] invalid argument.\n",
			MODULE_NAME);
			return -1;
		}
		/* set communication parameters */
		set_line_parameters(data->baseport, line_info);
		return 0;
	default:
		return -EINVAL;
	}
}

static int register_device_region(void)
{
	int err;
	int nb_devices;
	int first_minor;

	nb_devices = option == OPTION_BOTH ? 2 : 1;
	first_minor = option == OPTION_COM2 ? 1 : 0;

	err = register_chrdev_region(MKDEV(major, first_minor), nb_devices,
		MODULE_NAME);

	return err;
}

static void unregister_device_region(void)
{
	int nb_devices;
	int first_minor;

	nb_devices = option == OPTION_BOTH ? 2 : 1;
	first_minor = option == OPTION_COM2 ? 1 : 0;

	unregister_chrdev_region(MKDEV(major, first_minor), nb_devices);
}

static int request_IO_ports(void)
{
	/* Register COM1 port */
	if (device_registered[COM1]) {
		if (!request_region(COM1_BASEPORT, 8, MODULE_NAME))
			return -ENODEV;
	}
	/* Register COM2 port */
	if (device_registered[COM2]) {
		if (!request_region(COM2_BASEPORT, 8, MODULE_NAME)) {
			/* Free COM1 port if it was registered */
			if (device_registered[COM1])
				release_region(COM1_BASEPORT, 8);
			return -ENODEV;
		}
	}
	return 0;
}

static void free_IO_ports(void)
{
	/* Free COM1 port */
	if (device_registered[COM1])
		release_region(COM1_BASEPORT, 8);
	/* Free COM2 port */
	if (device_registered[COM2])
		release_region(COM2_BASEPORT, 8);
}

static int register_IRQ_handlers(void)
{
	int err;
	/* Register IRQ handler for COM1 */
	if (device_registered[COM1]) {
		err = request_irq(IRQ_COM1, interrupt_handler, IRQF_SHARED,
			MODULE_NAME, &devs[COM1]);
		if (err)
			return err;
	}
	/* Register IRQ handler for COM2 */
	if (device_registered[COM2]) {
		err = request_irq(IRQ_COM2, interrupt_handler, IRQF_SHARED,
			MODULE_NAME, &devs[COM2]);
		if (err) {
			/* Free IRQ for COM1 if it was registered */
			if (device_registered[COM1])
				free_irq(IRQ_COM1, &devs[COM1]);
			return err;
		}
	}
	return 0;
}

static void free_IRQ_handlers(void)
{
	/* Free IRQ for COM1 */
	if (device_registered[COM1])
		free_irq(IRQ_COM1, &devs[COM1]);
	/* Free IRQ for COM2 */
	if (device_registered[COM2])
		free_irq(IRQ_COM2, &devs[COM2]);
}

static void init_devs(void)
{
	int i;

	for (i = 0; i < MAX_NUMBER_DEVICES; i++) {
		if (device_registered[i]) {
			init_device_data(&devs[i], device_baseport[i]);
			cdev_init(&devs[i].cdev, &uart_fops);
			cdev_add(&devs[i].cdev, MKDEV(major, i), 1);
		}
	}
}

static void delete_devs(void)
{
	int i;

	for (i = 0; i < MAX_NUMBER_DEVICES; i++) {
		if (device_registered[i]) {
			clean_device_data(&devs[i]);
			cdev_del(&devs[i].cdev);
		}
	}
}

static int driver_init(void)
{
	int err;

	printk(LOG_LEVEL "%s: [driver_init] module init; params: major=%d, "
		"option=%d\n", MODULE_NAME, major, option);

	/* Handle arguments */
	if (option == OPTION_COM1)
		device_registered[COM1] = TRUE;
	else if (option == OPTION_COM2)
		device_registered[COM2] = TRUE;
	else {
		device_registered[COM1] = TRUE;
		device_registered[COM2] = TRUE;
	}

	/* Register device region */
	err = register_device_region();
	if (err) {
		printk(LOG_LEVEL "%s: [driver_init] Unable to register device "
			"region.\n", MODULE_NAME);
		return err;
	}

	/* Request I/O ports */
	err = request_IO_ports();
	if (err) {
		printk(LOG_LEVEL "%s: [driver_init] Unable to request IO "
			"ports.\n", MODULE_NAME);
		goto uregister_device;
	}

	/* Register IRQ handlers. */
	err = register_IRQ_handlers();
	if (err) {
		printk(LOG_LEVEL "%s: [driver_init] Unable to register IRQ "
			"handlers.\n", MODULE_NAME);
		goto free_IO_ports;
	}

	/* Init UART */
	if (device_registered[COM1])
		init_uart(COM1_BASEPORT);
	if (device_registered[COM2])
		init_uart(COM2_BASEPORT);

	/* Init & Add devices */
	init_devs();

	printk(LOG_LEVEL "%s: [driver_init] Driver loaded.\n", MODULE_NAME);
	return 0;

free_IO_ports:
	/* Free I/O ports */
	free_IO_ports();
uregister_device:
	/* Unregister device region */
	unregister_device_region();
	return err;
}

static void driver_exit(void)
{
	printk(LOG_LEVEL "%s: [driver_exit] module exit\n", MODULE_NAME);

	/* Delete devices */
	delete_devs();

	/* Free IRQ */
	free_IRQ_handlers();

	/* Free I/O ports */
	free_IO_ports();

	/* Unregister device region */
	unregister_device_region();

	printk(LOG_LEVEL "%s: [driver_exit] Driver unloaded.\n", MODULE_NAME);
}


module_init(driver_init);
module_exit(driver_exit);
