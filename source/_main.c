/*
 * Copyright (c) 2015 Sergi Granell (xerpi)
 */

#include "kernel.h"

#include "libc.h"
#include "network.h"
#include "pthread.h"

#include "ftp.h"

#define PS4_IP   "192.168.0.14"
#define PS4_PORT 1337

int _main(void)
{
	// Pass address of a syscall gadget in rcx
	register f rcx asm("rcx");
	directSyscall = rcx;

	// Init and resolve libraries
	initLibc();
	initNetwork();
	initPthread();

	ftp_init(PS4_IP, PS4_PORT);

	//INFO("PS4 listening on IP %s Port %i\n", PS4_IP, PS4_PORT);

	while (1) {
		// Delay thread
	}

	ftp_fini();

	return 0;
}
