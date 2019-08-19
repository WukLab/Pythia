#!/bin/bash
source ./setup.json
#make clean all
./init.o -b 1 -s 1 -c 2 -C 1 -I 2 -d $device -L 2 -M $interaction
#./init.o -b 1 -s 1 -c 2 -C 1 -I $1 -d 1 -L 2
