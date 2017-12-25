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

void custom_SHUTDOWN(ftps4_client_info_t *client) {
	ftps4_ext_client_send_ctrl_msg(client, "200 Shutting down..." FTPS4_EOL);
	run = 0;
}

char mount_from_path[PATH_MAX]; /* Yes, global. Lazy */

void custom_MTFR(ftps4_client_info_t *client)
{
	char from_path[PATH_MAX];
	/* Get the origin filename */
	ftps4_gen_ftp_fullpath(client, from_path, sizeof(from_path));

	/* The file to be renamed is the received path */
	strncpy(mount_from_path, from_path, sizeof(mount_from_path));
	ftps4_ext_client_send_ctrl_msg(client, "350 I need the destination name b0ss." FTPS4_EOL);
}

void custom_MTTO(ftps4_client_info_t *client)
{
	char path_to[PATH_MAX];
	struct iovec iov[8];
	char msg[512];
	char errmsg[255];
	int result;

	/* Get the destination filename */
	ftps4_gen_ftp_fullpath(client, path_to, sizeof(path_to));

	/* Just in case */
	unmount(path_to, 0);

	iov[0].iov_base = "fstype";
	iov[0].iov_len = sizeof("fstype");
	iov[1].iov_base = "nullfs";
	iov[1].iov_len = sizeof("nullfs");
	iov[2].iov_base = "fspath";
	iov[2].iov_len = sizeof("fspath");
	iov[3].iov_base = path_to;
	iov[3].iov_len = strlen(path_to) + 1;
	iov[4].iov_base = "target";
	iov[4].iov_len = sizeof("target");
	iov[5].iov_base = mount_from_path;
	iov[5].iov_len = strlen(mount_from_path) + 1;
	iov[6].iov_base = "errmsg";
	iov[6].iov_len = sizeof("errmsg");
	iov[7].iov_base = errmsg;
	iov[7].iov_len = sizeof(errmsg);
	result = nmount(iov, 8, 0);
	if (result < 0)
	{
		if (strlen(errmsg) > 0)
			snprintf(msg, sizeof(msg), "550 Could not mount (%d): %s." FTPS4_EOL, errno, errmsg);
		else
			snprintf(msg, sizeof(msg), "550 Could not mount (%d)." FTPS4_EOL, errno);
		ftps4_ext_client_send_ctrl_msg(client, msg);
		return;
	}

	ftps4_ext_client_send_ctrl_msg(client, "200 Mount success." FTPS4_EOL);
}

void custom_UMT(ftps4_client_info_t *client)
{
	char msg[512];
	int result;
	char mount_path[PATH_MAX];

	ftps4_gen_ftp_fullpath(client, mount_path, sizeof(mount_path));

	result = unmount(mount_path, 0);
	if (result < 0)
	{
		sprintf(msg, "550 Could not unmount (%d)." FTPS4_EOL, errno);
		ftps4_ext_client_send_ctrl_msg(client, msg);
		return;
	}

	ftps4_ext_client_send_ctrl_msg(client, "200 Unmount success." FTPS4_EOL);
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
	ftps4_ext_add_custom_command("SHUTDOWN", custom_SHUTDOWN);
	ftps4_ext_add_custom_command("MTFR", custom_MTFR);
	ftps4_ext_add_custom_command("MTTO", custom_MTTO);
	ftps4_ext_add_custom_command("UMT", custom_UMT);

	INFO("PS4 listening on IP %s Port %i\n", PS4_IP, PS4_PORT);

	while (run) {
		sceKernelUsleep(5 * 1000);
	}

	ftps4_fini();

	INFO("Bye!");

	sceNetSocketClose(log_sock);
	return 0;
}
