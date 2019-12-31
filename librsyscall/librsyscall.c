#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>

#include "../include/rsyscall.h"
#include "../include/librsyscall.h"

long rsyscall(pid_t pid, long number, ...)
{
	static int fd = -1;
	struct rsyscall_args rsargs;
	
	if (fd == -1) {
		fd = open("/dev/rsyscall", O_RDWR);
		if (fd == -1) {
			perror("open /dev/rsyscall");
			return -1;
		}
	}
	
	va_list argp;
	va_start(argp, number);
	
	rsargs.pid = pid;
	rsargs.sysno = number;
	rsargs.args[0] = va_arg(argp, long);
	rsargs.args[1] = va_arg(argp, long);
	rsargs.args[2] = va_arg(argp, long);
	rsargs.args[3] = va_arg(argp, long);
	rsargs.args[4] = va_arg(argp, long);
	rsargs.args[5] = va_arg(argp, long);
	
	va_end(argp);
	
	if (ioctl(fd, IOCTL_RSYSCALL, &rsargs) != 0) {
		perror("IOCTL_RSYSCALL");
		return -1;
	}
	
	return rsargs.retval;
}
