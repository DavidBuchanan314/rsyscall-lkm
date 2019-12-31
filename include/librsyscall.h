#pragma once

#include <sys/types.h>

long rsyscall(pid_t pid, long number, ...);
