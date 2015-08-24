/*
 * Copyright (c) 2015 Sergi Granell (xerpi)
 */

#include "ps4.h"
#include "ftp.h"

#define PS4_IP   "192.168.0.14"
#define PS4_PORT 1337

int _main(void)
{
	// Init and resolve libraries
	initKernel();
	initLibc();
	initNetwork();
	initPthread();

	ftp_init(PS4_IP, PS4_PORT);

	//INFO("PS4 listening on IP %s Port %i\n", PS4_IP, PS4_PORT);

	while (1) {
		sceKernelUsleep(100 * 1000);
	}

	ftp_fini();

	return 0;
}
