/*
 * Copyright (c) 2015 Sergi Granell (xerpi)
 */

#include "ps4.h"
#include "ftps4.h"

#undef  SHOW_DEBUG
#define PS4_IP   "192.168.0.22\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
#define PS4_PORT 1337
#define LOG_IP   "192.168.0.28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
#define LOG_PORT 9023

// DebugSettings
#define IP(a, b, c, d) (((a) << 0) + ((b) << 8) + ((c) << 16) + ((d) << 24))


#define	CTL_KERN	1	/* "high kernel": proc, limits */
#define	KERN_PROC	14	/* struct: process entries */
#define	KERN_PROC_VMMAP	32	/* VM map entries for process */
#define	KERN_PROC_PID	1	/* by process id */

struct auditinfo_addr {
    /*
    4    ai_auid;
    8    ai_mask;
    24    ai_termid;
    4    ai_asid;
    8    ai_flags;r
    */
    char useless[184];
};

#define printfsocket(format, ...)\
	do {\
		char buffer[512];\
		int size = sprintf(buffer, format, ##__VA_ARGS__);\
		sceNetSend(sock, buffer, size, 0);\
	} while(0)


unsigned int long long __readmsr(unsigned long __register) {
	// Loads the contents of a 64-bit model specific register (MSR) specified in
	// the ECX register into registers EDX:EAX. The EDX register is loaded with
	// the high-order 32 bits of the MSR and the EAX register is loaded with the
	// low-order 32 bits. If less than 64 bits are implemented in the MSR being
	// read, the values returned to EDX:EAX in unimplemented bit locations are
	// undefined.
	unsigned long __edx;
	unsigned long __eax;
	__asm__ ("rdmsr" : "=d"(__edx), "=a"(__eax) : "c"(__register));
	return (((unsigned int long long)__edx) << 32) | (unsigned int long long)__eax;
}


#define X86_CR0_WP (1 << 16)

static inline __attribute__((always_inline)) uint64_t readCr0(void) {
	uint64_t cr0;
	
	asm volatile (
		"movq %0, %%cr0"
		: "=r" (cr0)
		: : "memory"
 	);
	
	return cr0;
}

static inline __attribute__((always_inline)) void writeCr0(uint64_t cr0) {
	asm volatile (
		"movq %%cr0, %0"
		: : "r" (cr0)
		: "memory"
	);
}


struct ucred {
	uint32_t useless1;
	uint32_t cr_uid;     // effective user id
	uint32_t cr_ruid;    // real user id
 	uint32_t useless2;
    	uint32_t useless3;
    	uint32_t cr_rgid;    // real group id
    	uint32_t useless4;
    	void *useless5;
    	void *useless6;
    	void *cr_prison;     // jail(2)
    	void *useless7;
    	uint32_t useless8;
    	void *useless9[2];
    	void *useless10;
    	struct auditinfo_addr useless11;
    	uint32_t *cr_groups; // groups
    	uint32_t useless12;
};

struct filedesc {
	void *useless1[3];
    	void *fd_rdir;
    	void *fd_jdir;
};

struct proc {
    	char useless[64];
    	struct ucred *p_ucred;
    	struct filedesc *p_fd;
};

struct thread {
    	void *useless;
    	struct proc *td_proc;
};

struct kpayload_args{
	uint64_t user_arg;
};

// DebugSettings Definitions end here

int kpayload(struct thread *td, struct kpayload_args* args){

	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-0x30EB30];
	uint8_t* kernel_ptr = (uint8_t*)kernel_base;
	void** got_prison0 =   (void**)&kernel_ptr[0xF26010];
	void** got_rootvnode = (void**)&kernel_ptr[0x206D250];

	// resolve kernel functions

	int (*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kernel_base + 0x286d70);
	int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + 0x347580);

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;
	
	// uart enabler
	*(char *)(kernel_base + 0x186b0a0) = 0; // set the console disable console output bool

	// specters debug settings patchs
	*(char *)(kernel_base + 0x186b0a0) = 0; 
	*(char *)(kernel_base + 0x2001516) |= 0x14;
	*(char *)(kernel_base + 0x2001539) |= 1;
	*(char *)(kernel_base + 0x2001539) |= 2;
	*(char *)(kernel_base + 0x200153A) |= 1;
	*(char *)(kernel_base + 0x2001558) |= 1;	

	// Disable write protection

	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);

	// debug menu full patches thanks to sealab

	*(uint32_t *)(kernel_base + 0x4CECB7) = 0;
	*(uint32_t *)(kernel_base + 0x4CFB9B) = 0;

	// Target ID Patches :)

	*(uint16_t *)(kernel_base + 0x1FE59E4) = 0x8101;
	*(uint16_t *)(kernel_base + 0X1FE5A2C) = 0x8101;
	*(uint16_t *)(kernel_base + 0x200151C) = 0x8101;

	// Say hello and put the kernel base in userland so we can use later

	printfkernel("\n\n\nHELLO FROM YOUR KERN DUDE =)\n\n\n");

	printfkernel("kernel base is:0x%016llx\n", kernel_base);

	uint64_t uaddr;
	memcpy(&uaddr,&args[2],8);

	printfkernel("uaddr is:0x%016llx\n", uaddr);

	//copyout(&kernel_base, uaddr, 8);

	return 0;
}

// DebugSettings END
// DebugSettings END
// DebugSettings END
// DebugSettings END

int sock;
int run;

static void info_log(const char *s)
{
	sceNetSend(sock, s, strlen(s), 0);
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
	sceNetSend(sock, s, strlen(s), 0);
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


int _main(struct thread *td){

	run = 1;
	// Init and resolve libraries
	initKernel();
	initLibc();
	initNetwork();
	initPthread();

	// create our server
	struct sockaddr_in server;

	server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	sceNetInetPton(AF_INET, LOG_IP, &server.sin_addr);
	server.sin_port = sceNetHtons(LOG_PORT);
	//server.sin_addr.s_addr = IP(192, 168, 0, 22);
	//server.sin_port = sceNetHtons(9023);
	memset(server.sin_zero, 0, sizeof(server.sin_zero));
	
	//int sock = sceNetSocket("netdebug", AF_INET, SOCK_STREAM, 0);
	sock = sceNetSocket("netdebug", AF_INET, SOCK_STREAM, 0);
	sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));
	
	//Might be duplicate
	//int flag = 1;
	//sceNetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

	//nodump
	//uint64_t* dump = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);


	printfsocket("connected\n");

		
	// retreive the kernel base copied into userland memory and set it
	uint64_t kbase;

	//nodump
	//memcpy(&kbase,dump,8);

	printfsocket("kernBase is:0x%016llx\n",kbase);
	//nodump
	//printfsocket("dump is:0x%016llx\n",dump);

	// patch some things in the kernel (sandbox, prison, debug settings etc..)
	//int sRet = syscall(11,kpayload,td);
	//nodump
	//int sRet = syscall(11,kpayload,td,dump);


	printfsocket("kernel patched!\n");

	// kdump payload loop woz 'ere

	//nodump
	//free(dump);

	//sceNetSocketClose(sock);
    // return 0;

	//sock = sceNetSocket("netdebug", AF_INET, SOCK_STREAM, 0);
	//sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));

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

	int sRet = syscall(11,kpayload,td);

	while (run) {
		sceKernelUsleep(5 * 1000);
	}

	ftps4_fini();

	INFO("Bye!");

	sceNetSocketClose(sock);
	return 0;
}
