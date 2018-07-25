#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "ff3/ff3.h"
#include "ff3/ff_lib.h"

#include "nat_enc.h"

#define DEBUG 0
#define MSG_LEN 43

static uint8_t key[16];
keystruct rk;

static uint16_t rc5_key[2*(20+1)] = {0};

static uint8_t chacha_key[256/8] = {0};
static uint8_t chacha_iv[32/8] = {0};

void print_bytes (const char *prefix, uint8_t *msg, int msg_len) {
    int i;
    printf ("%s: 0x", prefix);

    for (i = 0; i < msg_len; i++) {
        printf ("%02x", msg[i]);
        if (((i + 1) % 8)==0)
            printf (" 0x");
    }
    printf ("\n");
}

#if DEBUG
#define NUM_EXP 1
#else
#define NUM_EXP 10000000
#endif
int main (void) {
	srand (time (NULL));
	uint64_t pt = (((uint64_t) rand ()) << 32) | rand ();
	uint64_t ct;
	uint64_t final;

	uint8_t tweak[8]={0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00};

	int i;

	struct timespec start, end;
	double t_enc_ns;
	double t_dec_ns;

	printf ("Running %d Experiments\n", NUM_EXP);

	init_key (&rk, key);

	printf ("\nTesting FF3 Encryption with %d-bit block...\n", MSG_LEN);
	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &start);

	for (i = 0; i < NUM_EXP; i++) {

		pt += 0x7af7795ff880;
		pt = pt & (((uint64_t)1 << MSG_LEN) - 1);
#if DEBUG
		printf ("PT: 0x%016" PRIx64 "\n", pt);
#endif
		nat_encrypt_ff3 ((uint8_t *)&pt, MSG_LEN, tweak, &rk, (uint8_t *)&ct);
#if DEBUG
		printf ("CT: 0x%016" PRIx64 "\n", ct);
#endif
	}

	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &end);
	t_enc_ns = (double)(end.tv_sec - start.tv_sec) * 1.0e9 +
	              (double)(end.tv_nsec - start.tv_nsec);

	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &start);

	pt = pt & (((uint64_t)1 << MSG_LEN) - 1);
	for (i = 0; i < NUM_EXP; i++) {
		ct = ct & (((uint64_t)1<<MSG_LEN) - 1);
		nat_decrypt_ff3 ((uint8_t *)&ct, MSG_LEN, tweak, &rk, (uint8_t *)&final);
#if DEBUG
		printf ("PT: 0x%016" PRIx64 "\n", final);
#endif
	}

	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &end);

	t_dec_ns = (double)(end.tv_sec - start.tv_sec) * 1.0e9 +
	              (double)(end.tv_nsec - start.tv_nsec);
	printf ("FF3 Encrypt: total time (%f), per-op (%f)\n", t_enc_ns, t_enc_ns/NUM_EXP);
	printf ("FF3 Decrypt: total time (%f), per-op (%f)\n", t_dec_ns, t_dec_ns/NUM_EXP);

	destroy_key (&rk);

	printf ("\nTesting RC5 Encryption with 32-bit block...\n");
	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &start);

	for (i = 0; i < NUM_EXP; i++) {
		pt += 0x7af7795ff880;
#if DEBUG
		print_bytes ("PT", (uint8_t *)&pt, 4);
#endif
		nat_encrypt_rc5 ((const uint32_t *)&pt, rc5_key, tweak, (uint32_t *)&ct);
#if DEBUG
		print_bytes ("CT", (uint8_t *)&ct, 4);
#endif
	}

	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &end);

	t_enc_ns = (double)(end.tv_sec - start.tv_sec) * 1.0e9 +
	              (double)(end.tv_nsec - start.tv_nsec);


	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &start);

	for (i = 0; i < NUM_EXP; i++) {
		nat_decrypt_rc5 ((const uint32_t *)&ct, rc5_key, tweak, (uint32_t *)&final);
#if DEBUG
		print_bytes ("PT", (uint8_t *)&final, 4);
#endif
	}

	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &end);

	t_dec_ns = (double)(end.tv_sec - start.tv_sec) * 1.0e9 +
	              (double)(end.tv_nsec - start.tv_nsec);
	printf ("RC5 Encrypt: total time (%f), per-op (%f)\n", t_enc_ns, t_enc_ns/NUM_EXP);
	printf ("RC5 Decrypt: total time (%f), per-op (%f)\n", t_dec_ns, t_dec_ns/NUM_EXP);

	printf ("\nTesting CHACHA20 Encryption with %d-bit block...\n", MSG_LEN);
	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &start);

	for (i = 0; i < NUM_EXP; i++) {
		pt += 0x7af7795ff880;
		pt = pt & (((uint64_t)1 << MSG_LEN) - 1);
#if DEBUG
		printf ("PT: 0x%016" PRIx64 "\n", pt);
#endif
		nat_encrypt_chacha20 ((const uint8_t *)&pt, MSG_LEN, chacha_key, 256, chacha_iv, 32, (uint8_t *)&ct);
#if DEBUG
		printf ("CT: 0x%016" PRIx64 "\n", ct);
#endif
	}

	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &end);

	t_enc_ns = (double)(end.tv_sec - start.tv_sec) * 1.0e9 +
	              (double)(end.tv_nsec - start.tv_nsec);


	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &start);

	for (i = 0; i < NUM_EXP; i++) {
		nat_decrypt_chacha20 ((const uint8_t *)&ct, MSG_LEN, chacha_key, 256, chacha_iv, 32, (uint8_t *)&final);
#if DEBUG
		printf ("PT: 0x%016" PRIx64 "\n", final);
#endif
	}

	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &end);

	t_dec_ns = (double)(end.tv_sec - start.tv_sec) * 1.0e9 +
	              (double)(end.tv_nsec - start.tv_nsec);
	printf ("CHA Encrypt: total time (%f), per-op (%f)\n", t_enc_ns, t_enc_ns/NUM_EXP);
	printf ("CHA Decrypt: total time (%f), per-op (%f)\n", t_dec_ns, t_dec_ns/NUM_EXP);

	return 0;
}
