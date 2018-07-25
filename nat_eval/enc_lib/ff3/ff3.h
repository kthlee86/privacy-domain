#ifndef _FF3_H_
#define _FF3_H_

#include <stdint.h>

#include "ff_lib.h"
#include "lib/aesni.h"

int ff3_encrypt (const uint8_t *pt, int len, const uint8_t *tweak,
                 const struct keystruct *rk,  uint8_t *ct);
int ff3_decrypt (const uint8_t *ct, int len, const uint8_t *tweak,
                 const struct keystruct *rk, uint8_t *pt);

#endif /*_FF3_H_*/
