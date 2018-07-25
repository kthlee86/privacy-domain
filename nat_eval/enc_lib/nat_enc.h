#include <openssl/sha.h>
#include <stdint.h>
#include <inttypes.h>

#include "rc5.h"
#include "ff3/ff3.h"
#include "chacha20/ecrypt-sync.h"

inline void nat_encrypt_ff3 (const uint8_t *pt, int len, const uint8_t *tweak, const keystruct *rk, uint8_t *ct) {
	ff3_encrypt (pt, len, tweak, rk, ct);
}

inline void nat_decrypt_ff3 (const uint8_t *ct, int len, const uint8_t *tweak, const keystruct *rk, uint8_t *pt) {
	ff3_decrypt (ct, len, tweak, rk, pt);
}

inline int sha1 (void* input, unsigned long length, unsigned char* md) {
	SHA_CTX context;

	if (!SHA1_Init (&context))
		return 0;

    if (!SHA1_Update(&context, (unsigned char*)input, length))
        return 0;

    if (!SHA1_Final(md, &context))
        return 0;

    return 1;
}

inline void nat_encrypt_rc5 (const uint32_t *pt, const uint16_t *key, uint8_t *hash, uint32_t *ct) {
	uint32_t *ptr32 = (uint32_t *)hash;
	uint32_t val;

	/*printf ("[%s]\n", __func__);*/

	val = *pt ^ *ptr32;

	/*printf ("encrypt input:  0x%08x\n", *ct);*/
	RC5_16_encrypt ((uint16_t *)&val, key);
	/*printf ("encrypt output: 0x%08x\n", *ct);*/

	*ct = val ^ *ptr32;
}

inline void nat_decrypt_rc5 (const uint32_t *ct, const uint16_t *key, uint8_t *hash, uint32_t *pt) {
	uint32_t *ptr32 = (uint32_t *)hash;
	uint32_t val;

	/*printf ("[%s]\n", __func__);*/

	val = *ct ^ *ptr32;

	/*printf ("decrypt input:  0x%08x\n", *pt);*/
	RC5_16_decrypt ((uint16_t *)&val, key);
	/*printf ("decrypt output: 0x%08x\n", *pt);*/

	*pt = val ^ *ptr32;
}

#if 0
inline void chacha20_init (void) {
	ECRYPT_init();
}

inline void nat_setkey_chacha20 (ECRYPT_ctx *ctx,
								 uint8_t *key, int keylen,
								 uint8_t *iv, int ivlen) {
	ECRYPT_keysetup (ctx, key, keylen, ivlen);
	ECRYPT_ivsetup (ctx, iv);
}

/*
	Everything in bits
*/
inline void nat_encrypt_chacha20 (ECRYPT_ctx *ctx,
								  uint8_t *pt, int len,
								  uint8_t *ct) {
	int nblocks = (len + 7) >> 3;
	ECRYPT_encrypt_bytes (ctx, pt, ct, nblocks);
}

/*
	Everything in bits
*/
inline void nat_decrypt_chacha20 (ECRYPT_ctx *ctx,
								  uint8_t *ct, int len,
								  uint8_t *pt) {
	nat_encrypt_chacha20 (ctx, ct, len, pt);
}
#endif
