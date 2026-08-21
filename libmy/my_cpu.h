#ifndef MY_CPU_H
#define MY_CPU_H

#include <unistd.h>

#ifdef __linux__
# include <sched.h>
#endif /* __linux__ */

/* Cores this process may actually run on. Never less than one. */
static inline long
my_ncpu(void)
{
	long ncpu = -1;

#ifdef __linux__
	cpu_set_t set;

	if (sched_getaffinity(0, sizeof(set), &set) == 0)
		ncpu = CPU_COUNT(&set);
#endif /* __linux__ */

	if (ncpu < 1)
		ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpu < 1)
		ncpu = 1;

	return (ncpu);
}

#endif /* MY_CPU_H */
