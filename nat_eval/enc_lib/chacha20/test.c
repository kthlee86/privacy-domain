#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "ecrypt-sync.h"

static uint8_t key[256/8] = {1};
static uint8_t iv[32/8] = {2};

#define MSG_LEN (5)

void print_bytes (const char *prefix, uint8_t *msg, int msg_len) {
	int i;
	printf ("%s: ", prefix);

	for (i = 0; i < msg_len; i++) {
		printf ("%02x", msg[i]);
		if (((i + 1) % 8)==0)
			printf (" ");
	}
	printf ("\n");
}

int main (void) {
	uint8_t pt[MSG_LEN];
	uint8_t ct[MSG_LEN];
	uint8_t fi[MSG_LEN];

	ECRYPT_ctx ctx, ctx2;

	ECRYPT_init();

	srand (time (NULL));

	int i = 0;
	for (int i = 0; i < MSG_LEN; i++) {
		pt [i] = rand ();
	}

	for (i = 0; i < 1; i++) {
		printf ("\n");
		ECRYPT_keysetup (&ctx, key, 256, 32);
		ECRYPT_ivsetup (&ctx, iv);

		print_bytes ("PT", pt, MSG_LEN);
		ECRYPT_encrypt_bytes (&ctx, pt, ct, MSG_LEN);
		print_bytes ("CT", ct, MSG_LEN);

		ct[MSG_LEN-1] &= 0xfe;

		ECRYPT_keysetup (&ctx2, key, 256, 32);
		ECRYPT_ivsetup (&ctx2, iv);

		print_bytes ("CT", ct, MSG_LEN);
		ECRYPT_decrypt_bytes (&ctx2, ct, fi, MSG_LEN);
		print_bytes ("PT", fi, MSG_LEN);
	}
	return 0;
}
