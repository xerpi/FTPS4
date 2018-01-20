#ifndef __DEFINES
#define __DEFINES

//#define DEBUG_SOCKET

#ifdef DEBUG_SOCKET
  extern int sock;
  #define printfsocket(format, ...)\
    do {\
    char __printfsocket_buffer[512];\
    int __printfsocket_size = sprintf(__printfsocket_buffer, format, ##__VA_ARGS__);\
    sceNetSend(sock, __printfsocket_buffer, __printfsocket_size, 0);\
  } while(0)
#else
	#define printfsocket(format, ...) (void)0
#endif

#endif
