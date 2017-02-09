/*
 * Copyright (c) 2015 Sergi Granell (xerpi)
 */

#ifndef FTP_H
#define FTP_H

#include "types.h"

/* Pass PS4's IP and FTP port */
void ftp_init(const char *ip, unsigned short int port);
void ftp_fini();


#endif
