#ifndef _FF_LIB_H_
#define _FF_LIB_H_

#include <stdint.h>

#include "lib/aesni.h"

inline void init_key (keystruct *rk, uint8_t *key) {
	rk->roundkey = aes_assembly_init (key);
}

inline void destroy_key (keystruct *rk) {
	free_aligned (rk->roundkey);
}

inline uint32_t bit_reverse32 (uint32_t v) {
	static const unsigned char BitReverseTable256[256] = {
		#   define R2(n)     n,     n + 2*64,     n + 1*64,     n + 3*64
		#   define R4(n) R2(n), R2(n + 2*16), R2(n + 1*16), R2(n + 3*16)
		#   define R6(n) R4(n), R4(n + 2*4 ), R4(n + 1*4 ), R4(n + 3*4 )
		R6(0), R6(2), R6(1), R6(3)
	};

	uint32_t c; // c will get v reversed

#if 1
	// Option 1:
	c = (BitReverseTable256[v & 0xff] << 24) |
		(BitReverseTable256[(v >> 8) & 0xff] << 16) |
		(BitReverseTable256[(v >> 16) & 0xff] << 8) |
		(BitReverseTable256[(v >> 24) & 0xff]);
#else
	// Option 2:
	uint8_t * p = (uint8_t *) &v;
	uint8_t * q = (uint8_t *) &c;
	q[3] = BitReverseTable256[p[0]];
	q[2] = BitReverseTable256[p[1]];
	q[1] = BitReverseTable256[p[2]];
	q[0] = BitReverseTable256[p[3]];
#endif
	return c;
}

/*
	m must be <=32
*/
inline uint32_t bit_reverse_m (uint32_t v, int m) {
	return bit_reverse32 (v) >> (32 - m);
}

#endif /* _FF_LIB_H_ */
