#define _GNU_SOURCE
#include <stdlib.h> // For malloc
#include <stdint.h> // uint64_t

// Measure_read
#define measure(_memory, _time)        \
	do                                 \
	{                                  \
		register uint32_t _delta;      \
		asm volatile(                  \
			"rdtscp;"                  \
			"mov %%eax, %%esi;"        \
			"mov (%%rbx), %%eax;"      \
			"rdtscp;"                  \
			"mfence;"                  \
			"sub %%esi, %%eax;"        \
			"mov %%eax, %%ecx;"        \
			: "=c"(_delta)             \
			: "b"(_memory)             \
			: "esi", "r11");           \
		*(uint32_t *)(_time) = _delta; \
	} while (0)
