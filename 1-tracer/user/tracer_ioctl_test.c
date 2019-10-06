/*
 * SO2 Lab - Linux device drivers (#4)
 * User-space test file
 */

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "../tracer.h"
#include <time.h>
#include <stdlib.h>

#define DEVICE_PATH	"/dev/tracer"

static void usage(const char *argv0)
{
	printf("Usage: %s <options>\n options:\n"
			"\ta - add_process\n"
			"\tr - remove_process\n", argv0);
	exit(EXIT_FAILURE);
}

static void add_process(int fd)
{
  if (ioctl(fd, TRACER_ADD_PROCESS, rand() % 10) < 0) {
    printf("[error] ioctl\n");
    /* handle error */
    close(fd);
  	return;
  }
}

static void remove_process(int fd)
{
  if (ioctl(fd, TRACER_REMOVE_PROCESS, rand() % 10) < 0) {
    printf("[error] ioctl\n");
    /* handle error */
    close(fd);
  	return;
  }
}

int main(int argc, char **argv)
{
	int fd;

  srand(time(NULL));

	if (argc < 2)
		usage(argv[0]);

	if (strlen(argv[1]) != 1)
		usage(argv[0]);
	
	fd = open(DEVICE_PATH, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	switch (argv[1][0]) {
	case 'a':
		add_process(fd);
		break;
	case 'r':
		remove_process(fd);
		break;
	default:
		usage(argv[0]);
	}

	close(fd);

	return 0;
}
