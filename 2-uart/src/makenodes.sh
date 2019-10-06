#!/bin/sh

device="uart"
major=42

rm -f /dev/${device}[0-1]

mknod /dev/${device}0 c $major 0
mknod /dev/${device}1 c $major 1
