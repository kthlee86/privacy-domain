#ifndef _NAT_H_
#define _NAT_H_

#include <stdint.h>
#include "enc_lib/ff3/lib/aesni.h"
#include "enc_lib/chacha20/ecrypt-sync.h"

#ifndef DPDK
#define DPDK (1)
#endif

#if DPDK
#define RTE_LOGTYPE_NAT RTE_LOGTYPE_USER1
#endif

void setup_nat_table (const int socketid);
void *get_nat_table (const int socketid);
void destroy_nat_table (const int socketid);

int process_outgoing_pkt (void *nat_table, void *ip_hdr);
int process_incoming_pkt (void *nat_table, void *ip_hdr);

#endif /* _NAT_H_ */
