#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include "aesni.h"


#if (INT_MAX != 0x7fffffff)
#error -- Assumes 4-byte int
#endif


void *malloc_aligned(size_t alignment, size_t bytes)
{
    const size_t total_size = bytes + (2 * alignment) + sizeof(size_t);

    // use malloc to allocate the memory.
    char *data = malloc(sizeof(char) * total_size);

    if (data)
    {
        // store the original start of the malloc'd data.
        const void * const data_start = data;

        // dedicate enough space to the book-keeping.
        data += sizeof(size_t);

        // find a memory location with correct alignment. the alignment minus
        // the remainder of this mod operation is how many bytes forward we need
        // to move to find an aligned byte.
        const size_t offset = alignment - (((size_t)data) % alignment);

        // set data to the aligned memory.
        data += offset;

        // write the book-keeping.
        size_t *book_keeping = (size_t*)(data - sizeof(size_t));
        *book_keeping = (size_t)data_start;
    }

    return data;
}

void free_aligned(void *raw_data)
{
    if (raw_data)
    {
        char *data = raw_data;

        // we have to assume this memory was allocated with malloc_aligned.
        // this means the sizeof(size_t) bytes before data are the book-keeping
        // which points to the location we need to pass to free.
        data -= sizeof(size_t);

        // set data to the location stored in book-keeping.
        data = (char*)(*((size_t*)data));

        // free the memory.
        free(data);
    }
}

unsigned char* aes_assembly_init(void *enc_key)
{
    if (enc_key != NULL) {
    	unsigned char* roundkey = (unsigned char*)malloc_aligned(16, 10*16*sizeof(char));
    	memset(roundkey, 0, sizeof(10*16*sizeof(char)));
    	ExpandKey128(enc_key, roundkey);
    	return roundkey;
    }
}


#if 0
int main(int argc, char *argv[])
{
	unsigned char key[16];

	struct keystruct rk;
	rk.roundkey = aes_assembly_init(key);

	unsigned char input[16];
	unsigned char mac[16];
	unsigned long long t1 = 0;
	unsigned long long t2 = 0;
	unsigned long long result = 0;

	int tmp;
	int i;
	int l;
	double runtotal;

	srand(time(NULL));
	for(l=0;l<50;l++){
		result = 0;
		for(i=0;i<500000;i++){
			for (int k = 0; k < 16; k++) {
				key[k] = (rand()) % 256;
				input[k] = (rand()) % 256;
			}
			rk.roundkey = aes_assembly_init(key);

			t1 = _do_rdtsc();
			CMAC(rk.roundkey, 1, input, mac);
			t2 = _do_rdtsc();
			tmp += mac[2];
			result += t2-t1;
		}
		runtotal+= (double)(result)/500000;

		printf("cycle(CMAC) run %d = %f. throwawayvalue: %d\n", l, (double)(result)/500000, tmp);
	}

	printf("Average cycles: %d", runtotal/50);

	free_aligned(rk.roundkey);
	return 0;
}
#endif

