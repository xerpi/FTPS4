/*
 * Copyright (c) 2015 Sergi Granell (xerpi)
 */

#include "ps4.h"
#include "ftps4.h"

#undef  SHOW_DEBUG
#define PS4_IP   "192.168.0.14"
#define PS4_PORT 1337
#define LOG_IP   "192.168.0.4"
#define LOG_PORT 9023

int log_sock;
int run;

static void info_log(const char *s)
{
	sceNetSend(log_sock, s, strlen(s), 0);
}
#define INFO(...) \
	do { \
		char buf[512]; \
		sprintf(buf, ##__VA_ARGS__); \
		info_log(buf); \
	} while(0)

#ifdef SHOW_DEBUG
static void debug_log(const char *s)
{
	sceNetSend(log_sock, s, strlen(s), 0);
}
#define DEBUG(...) \
	do { \
		char buf[512]; \
		sprintf(buf, ##__VA_ARGS__); \
		info_log(buf); \
	} while(0)
#else
#define DEBUG(...)
#endif

void ftps4_SHUTDOWN(ftps4_client_info_t *client) {
	ftps4_ext_client_send_ctrl_msg(client, "200 Shutting down..." FTPS4_EOL);
	run = 0;
}

int _main(void)
{
	run = 1;

	// Init and resolve libraries
	initKernel();
	initLibc();
	initNetwork();
	initPthread();

	// Init netdebug
	struct sockaddr_in server;
	server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	sceNetInetPton(AF_INET, LOG_IP, &server.sin_addr);
	server.sin_port = sceNetHtons(LOG_PORT);
	memset(server.sin_zero, 0, sizeof(server.sin_zero));

	log_sock = sceNetSocket("netdebug", AF_INET, SOCK_STREAM, 0);
	sceNetConnect(log_sock, (struct sockaddr *)&server, sizeof(server));

	ftps4_set_info_log_cb(info_log);
#ifdef SHOW_DEBUG
	ftps4_set_debug_log_cb(debug_log);
#endif

	ftps4_init(PS4_IP, PS4_PORT);
	ftps4_ext_add_custom_command("SHUTDOWN", ftps4_SHUTDOWN);

	INFO("PS4 listening on IP %s Port %i\n", PS4_IP, PS4_PORT);

	while (run) {
		sceKernelUsleep(5 * 1000);
	}

	ftps4_fini();

	INFO("Bye!");

	sceNetSocketClose(log_sock);
	return 0;
}
