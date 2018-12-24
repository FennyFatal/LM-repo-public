#ifndef __DEFINES
#define __DEFINES

#define VERSION "1.3.2"
#define	static_assert	_Static_assert

//#define DEBUG_SOCKET

#define FTP_PORT 21

#define LOG_IP   "192.168.1.3\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
#define LOG_PORT 9023

#define PATH_MAX 255

#define CHECK_SIZE(x, y) static_assert(sizeof(x) == y, #x)

#define	MNT_UPDATE	0x0000000000010000ULL /* not real mount, just update */

#endif
