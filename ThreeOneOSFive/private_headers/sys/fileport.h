// Stub for sys/fileport.h — private XNU header not in public iOS SDK
// fileport_makeport and fileport_makefd are libSystem symbols, declared here for compilation.

#ifndef _SYS_FILEPORT_H_
#define _SYS_FILEPORT_H_

#include <mach/port.h>

typedef mach_port_t fileport_t;

extern int fileport_makeport(int fd, fileport_t *portnamep);
extern int fileport_makefd(fileport_t port);

#endif /* _SYS_FILEPORT_H_ */
