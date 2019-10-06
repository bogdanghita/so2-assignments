#!/bin/sh

device="case"
major=42

rm -f /dev/${device} /dev/${device}[0-8]
mknod /dev/${device}0 c $major 0
mknod /dev/${device}1 c $major 1
mknod /dev/${device}2 c $major 2
mknod /dev/${device}3 c $major 3
mknod /dev/${device}4 c $major 4
mknod /dev/${device}5 c $major 5
mknod /dev/${device}6 c $major 6
mknod /dev/${device}7 c $major 7
mknod /dev/${device}8 c $major 8
ln -sf ${device}0 /dev/${device}

