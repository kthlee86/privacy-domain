#include <stdint.h>

#define RC5_16_MASK (0xffff)

#if 0
#define ROTATE_l16(a,n)   ({ register unsigned int ret;   \
		asm ("roll %%cl,%0" \
				: "=r"(ret) \
				: "c"(n),"0"((unsigned int)(a)) \
				: "cc");    \
		ret;            \
		})

#define ROTATE_r16(a,n)   ({ register unsigned int ret;   \
		asm ("rorl %%cl,%0" \
				: "=r"(ret) \
				: "c"(n),"0"((unsigned int)(a)) \
				: "cc");    \
		ret;            \
		})
#else
#define ROTATE_l16(a,n)     (((a)<<(n&0xf))|(((a)&0xffff)>>(16-(n&0xf))))
#define ROTATE_r16(a,n)     (((a)<<(16-(n&0xf)))|(((a)&0xffff)>>(n&0xf)))
#endif

#define E_RC5_16(a,b,s,n) \
			a^=b; \
			a=ROTATE_l16(a,b); \
			a+=s[n]; \
			a&=RC5_16_MASK; \
			b^=a; \
			b=ROTATE_l16(b,a); \
			b+=s[n+1]; \
			b&=RC5_16_MASK;

#define D_RC5_16(a,b,s,n) \
			b-=s[n+1]; \
			b&=RC5_16_MASK; \
			b=ROTATE_r16(b,a); \
			b^=a; \
			a-=s[n]; \
			a&=RC5_16_MASK; \
			a=ROTATE_r16(a,b); \
			a^=b;

inline void RC5_16_encrypt(uint16_t *d, const uint16_t *key) {
    uint16_t a, b;
	const uint16_t *s;

    s = key;

    a = d[0] + s[0];
    b = d[1] + s[1];

	/*printf ("[%s] d[0](%d) s[0](%d) d[1](%d) s[1](%d)\n", __func__, d[0], s[0], d[1], s[1]);*/

	E_RC5_16(a, b, s, 2);
	E_RC5_16(a, b, s, 4);
	E_RC5_16(a, b, s, 6);
	E_RC5_16(a, b, s, 8);
	E_RC5_16(a, b, s, 10);

	E_RC5_16(a, b, s, 12);
	E_RC5_16(a, b, s, 14);
	E_RC5_16(a, b, s, 16);
	E_RC5_16(a, b, s, 18);
	E_RC5_16(a, b, s, 20);

	E_RC5_16(a, b, s, 22);
	E_RC5_16(a, b, s, 24);
	E_RC5_16(a, b, s, 26);
	E_RC5_16(a, b, s, 28);
	E_RC5_16(a, b, s, 30);

	E_RC5_16(a, b, s, 32);
	E_RC5_16(a, b, s, 34);
	E_RC5_16(a, b, s, 36);
	E_RC5_16(a, b, s, 38);
	E_RC5_16(a, b, s, 40);

    d[0] = a;
    d[1] = b;
}

inline void RC5_16_decrypt(uint16_t *d, const uint16_t *key) {
	uint16_t a, b;
	const uint16_t *s;

	s = key;

	a = d[0];
	b = d[1];

	D_RC5_16(a, b, s, 40);
	D_RC5_16(a, b, s, 38);
	D_RC5_16(a, b, s, 36);
	D_RC5_16(a, b, s, 34);
	D_RC5_16(a, b, s, 32);

	D_RC5_16(a, b, s, 30);
	D_RC5_16(a, b, s, 28);
	D_RC5_16(a, b, s, 26);
	D_RC5_16(a, b, s, 24);
	D_RC5_16(a, b, s, 22);

	D_RC5_16(a, b, s, 20);
	D_RC5_16(a, b, s, 18);
	D_RC5_16(a, b, s, 16);
	D_RC5_16(a, b, s, 14);
	D_RC5_16(a, b, s, 12);

	D_RC5_16(a, b, s, 10);
	D_RC5_16(a, b, s, 8);
	D_RC5_16(a, b, s, 6);
	D_RC5_16(a, b, s, 4);
	D_RC5_16(a, b, s, 2);

	d[0] = a - s[0];
	d[1] = b - s[1];
}
