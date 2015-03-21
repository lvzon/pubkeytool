CC=gcc
STRIP=strip

pkt: pubkeytool.c
	$(CC) -Os -DTFM_DESC -DMECC_FP -o pkt pubkeytool.c -ltomcrypt -ltfm -lm
	$(STRIP) pkt

pkt-debug: pubkeytool.c
	$(CC) -g -DDEBUG -DTFM_DESC -DMECC_FP -o pkt-debug pubkeytool.c -ltomcrypt -ltfm -lm

