/*
 * Coded by SiSTRo - Credits to flat_z
 */

#ifndef REMOUNT_H
#define REMOUNT_H

#define	MNT_RDONLY	0x0000000000000001ULL
#define	MNT_UPDATE	0x0000000000010000ULL

int remount_system_partition();
int remount_system_ex_partition();

#endif