#!/bin/sh

OPTION_COM1_ONLY=1
OPTION_COM2_ONLY=2
OPTION_BOTH=3

module_name="uart16550"
major=42
option=$OPTION_BOTH

insmod ${module_name}.ko major=${major} option=${option}