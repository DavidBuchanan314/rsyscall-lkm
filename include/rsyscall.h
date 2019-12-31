#pragma once

struct rsyscall_args {
	pid_t pid;
	long sysno;
	long args[6];
	long retval;
};

#define IOCTL_RSYSCALL_TYPE 42 // arbitrary number
#define IOCTL_RSYSCALL _IOWR(IOCTL_RSYSCALL_TYPE, 1, struct rsyscall_args)
