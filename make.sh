#!/bin/sh

#gcc -g -DDEBUG -DTFM_DESC -DMECC_FP -o pkt pubkeytool.c -ltomcrypt -ltfm -lm
gcc -DTFM_DESC -DMECC_FP -o pkt pubkeytool.c -ltomcrypt -ltfm -lm
