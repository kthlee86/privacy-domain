#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ff3.h"
#include "ff_lib.h"
#include "lib/aesni.h"

#undef DEBUG

#define NUM_ROUNDS 8

#define BS1_LEN (4)
#define BS2_LEN (12)
#define P_LEN (BS1_LEN + BS2_LEN)

/*
	len: in bits

	Assumptions:
		- radix of 2
		- len equal or less than 48 bits; however, ct and pt buffer are 8 bytes long
		- byte order of the key has been reversed, i.e., REVB (key)
*/
int ff3_encrypt (const uint8_t *pt, int len, const uint8_t *tweak, const keystruct *rk, uint8_t *ct) {
	int8_t i;
	int32_t c;
	uint32_t u, v, m, W, A, B;
	int64_t y, t;
	const uint32_t *T_L, *T_R;
	int64_t *ptr64;
	int8_t P[P_LEN], T[P_LEN];

	if (__builtin_expect (len > 48, 0))
		return -1;

	/* Step 1 */
	v = len / 2;
	u = len - v;

#ifdef DEBUG
	printf ("[%s] len (%d) u_len (%d) v_len (%d)\n", __func__, len, u, v);
#endif

	/* Step 2 */
	A = (uint32_t) ((*(const uint64_t *)pt) >> v);
	B = ((*(const uint32_t *)pt) << (32 - v)) >> (32 - v);

	/* Step 3 */
	T_L = (const uint32_t *)(tweak + 4);	// little-endianness
	T_R = (const uint32_t *)tweak;

	/*
		For optimization, eliminate bit reversal operation within the for loop
	*/
	A = bit_reverse_m (A, u);
	B = bit_reverse_m (B, v);

	/* Step 4 */
	for (i = 0; i < NUM_ROUNDS; i++) {
		/* Step 4i */
		if (!(i & 1)) {
			m = u;
			W = *T_R;
		}
		else {
			m = v;
			W = *T_L;
		}

#ifdef DEBUG
		printf ("[Round %d] m: %d\n", i + 1, m);
		printf ("A: 0x%08x\n", bit_reverse_m (A, m));
		printf ("B: 0x%08x\n", bit_reverse_m (B, len - m));
#endif

		/* Step 4ii + REVB (P) of Step 4iii */
		bzero (T, P_LEN);
		/*    LSB 4 bytes: REVB (W xor [i]^4) */
		W = __builtin_bswap32 (W);
		memcpy (T, &W, 4);
		T[3] ^= i;

		/*    MSB 12 bytes: REVB (NUM (REV (B))) */
		t = __builtin_bswap32 (B);
		memcpy (T+12, &t, 4);

		/* Step 4iii + 4iv */
		CBCMAC (rk->roundkey, 1, (uint8_t *)T, (uint8_t *)P);
		/*
		   Let T = CIPH (.) and T = [T1 T2 T3 ... T16]
		   Then,
		   		S = REVB (T) corresponds to S = [T16 T15 ... T1]
				y: num(S) corresponds to y = T16|T15|T14|...|T1
					Since our architecture is in little-endian, we need the memory structure to be
					[T1 T2 ... T16] to get y. Hence, we take S = T, instead of S = REVB (T)
		*/
		ptr64 = (int64_t *)P;
		y = *ptr64;
#ifdef DEBUG
		printf ("y: 0x%016" PRIx64 "\n", y);
#endif

		/* NUM_{radix}(REV(A)) of Step 4v */
		t = (int64_t)A;
#ifdef DEBUG
		printf ("t: 0x%016" PRIx64 "\n", t);
#endif
		/* Step 4v + Step 4vi */
		c = (y + t) & ((1 << m) - 1);
		/*c = ((y + t) << (32 - m )) >> (32 + m);*/
#ifdef DEBUG
		printf ("c: 0x%08" PRIx32 "\n", c);
		printf ("C: 0x%08x\n", bit_reverse_m (c, m));
#endif

		/* Step 4vii + Step 4viii */
		A = B;
		B = c;
#ifdef DEBUG
		printf ("\n");
#endif
	}

	*(uint64_t *)ct = (((uint64_t)bit_reverse_m (A, u))<<v) | (uint64_t)bit_reverse_m (B, v);
#ifdef DEBUG
	printf("ct: 0x%016" PRIx64 "\n", *(uint64_t *)ct);
#endif

	return 0;
}

/*
	len: in bits

	Assumptions:
		- radix of 2
		- len equal or less than 48 bits; however, ct and pt buffer are 8 bytes long
		- byte order of the key has been reversed, i.e., REVB (key)
*/
int ff3_decrypt (const uint8_t *ct, int len, const uint8_t *tweak, const keystruct *rk, uint8_t *pt) {
	int8_t i;
	int32_t c;
	uint32_t u, v, m, W, A, B;
	int64_t y, t;
	const uint32_t *T_L, *T_R;
	int64_t *ptr64;
	int8_t P[P_LEN], T[P_LEN];

	if (__builtin_expect (len > 48, 0))
		return -1;

	/* Step 1 */
	v = len / 2;
	u = len - v;

#ifdef DEBUG
	printf ("[%s] len (%d) u_len (%d) v_len (%d)\n", __func__, len, u, v);
#endif

	/* Step 2 */
	A = (uint32_t) ((*(const uint64_t *)ct) >> v);
	B = ((*(const uint32_t *)ct) << (32 - v)) >> (32 - v);

	/* Step 3 */
	T_L = (const uint32_t *)(tweak + 4);	// little-endianness
	T_R = (const uint32_t *)tweak;

	/*
		For optimization, eliminate bit reversal operation within the for loop
	*/
	A = bit_reverse_m (A, u);
	B = bit_reverse_m (B, v);

	/* Step 4 */
	for (i = NUM_ROUNDS - 1; i >= 0; i--) {
		/* Step 4i */
		if (!(i & 1)) {
			m = u;
			W = *T_R;
		}
		else {
			m = v;
			W = *T_L;
		}

#ifdef DEBUG
		printf ("[Round %d] m: %d\n", i + 1, m);
		printf ("A: 0x%08x\n", bit_reverse_m (A, len - m));
		printf ("B: 0x%08x\n", bit_reverse_m (B, m));
#endif

		/* Step 4ii + REVB (P) of Step 4iii*/
		bzero (T, P_LEN);
		/*    LSB 4 bytes: REVB (W xor [i]^4) */
		W = __builtin_bswap32 (W);
		memcpy (T, &W, 4);
		T[3] ^= i;

		/*    MSB 12 bytes: REVB (NUM (REV (A))) */
		t = __builtin_bswap32 (A);
		memcpy (P+12, &t, 4);

		/* Step 4iii + 4iv */
		CBCMAC (rk->roundkey, 1, (uint8_t *)T, (uint8_t *)P);
		/*
		   Let T = CIPH (.) and T = [T1 T2 T3 ... T16]
		   Then,
		   		S = REVB (T) corresponds to S = [T16 T15 ... T1]
				y: num(S) corresponds to y = T16|T15|T14|...|T1
					Since our architecture is in little-endian, we need the memory structure to be
					[T1 T2 ... T16] to get y. Hence, we take S = T, instead of S = REVB (T)
		*/
		ptr64 = (int64_t *)P;
		y = *ptr64;
#ifdef DEBUG
		printf ("y: 0x%016" PRIx64 "\n", y);
#endif

		/* NUM_{radix}(REV(A)) of Step 4v */
		t = (int64_t)B;
#ifdef DEBUG
		printf ("t: 0x%016" PRIx64 "\n", t);
#endif
		/* Step 4v + Step 4vi*/
		c = (t - y) & ((1 << m) - 1);
		/*c = ((t - y) << (32 - m )) >> (32 + m);*/
#ifdef DEBUG
		printf ("c: 0x%08" PRIx32 "\n", c);
		printf ("C: 0x%08x\n", bit_reverse_m (c, m));
#endif
		/* Step 4vii + Step 4viii */
		B = A;
		A = c;
#ifdef DEBUG
		printf ("\n");
#endif
	}

	*(uint64_t *)pt = (((uint64_t)bit_reverse_m (A, u))<<v) | (uint64_t) bit_reverse_m (B, v);
#ifdef DEBUG
	printf("pt: 0x%016" PRIx64 "\n", *(uint64_t *)pt);
#endif

	return 0;
}
