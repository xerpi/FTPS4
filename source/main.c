/*
 * Copyright (c) 2015 Sergi Granell (xerpi)
 */

#include "ps4.h"
#include "ftp.h"

#define PS4_IP   "192.168.0.14"
#define PS4_PORT 1337

int netdbg_sock;

int _main(void)
{
	// Init and resolve libraries
	initKernel();
	initLibc();
	initNetwork();
	initPthread();

	// Init netdebug
	struct sockaddr_in server;
	server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = IP(192, 168, 0, 4);
	server.sin_port = sceNetHtons(9023);
	memset(server.sin_zero, 0, sizeof(server.sin_zero));

	netdbg_sock = sceNetSocket("netdebug", AF_INET, SOCK_STREAM, 0);
	sceNetConnect(netdbg_sock, (struct sockaddr *)&server, sizeof(server));


	ftp_init(PS4_IP, PS4_PORT);

	//INFO("PS4 listening on IP %s Port %i\n", PS4_IP, PS4_PORT);

	while (1) {
		sceKernelUsleep(100 * 1000);
	}

	ftp_fini();

	return 0;
}
