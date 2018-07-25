#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>

#include "nat.h"
#include "enc_lib/nat_enc.h"

#if DPDK
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_hash.h>
#include "l3fwd.h"
#else
#define NB_SOCKETS (1)
#define IPv4(a,b,c,d) (((uint32_t)(a&0xff)<<24) + ((b&0xff)<<16) + ((c&0xff)<<8) + (d&0xff))
#endif

/*const char *rtbl_file = "rtable/prefix_to_idx_16block";*/
/*#define NUM_ADDR (16)	// 2^16 addresses*/

/*const char *rtbl_file = "rtable/prefix_to_idx_8block";*/
/*#define NUM_ADDR (24)	// 2^24 addresses*/

const char *rtbl_file = "rtable/prefix_to_idx_japan_as4134";
#define NUM_ADDR (26)	// 2^26 addresses

#define BLOCK_LEN (NUM_ADDR + 16)
#define HOST_MASK ((1<<(NUM_ADDR)) - 1)

#define CHACHA20 0
#define FF3 1
#define RC5 2

/*#define CRYPTO_ALG CHACHA20*/
#define CRYPTO_ALG FF3
/*#define CRYPTO_ALG RC5*/

#define CHECKSUM 0

/*#define DEBUG*/

typedef struct ff3_msg {
	uint64_t port:16,
			 host:NUM_ADDR,
			 rem:(64 - 16 - NUM_ADDR);
}__attribute__((packed)) ff3_msg_t;

struct ipv4_5tuple_host {
	uint8_t proto;
	uint16_t pad1;
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
};

#if CRYPTO_ALG == CHACHA20
static uint8_t chacha_key[256/8] = {0};
static uint8_t chacha_iv[32/8] = {0};
static ECRYPT_ctx chacha_ctx;
#endif
#if CRYPTO_ALG == RC5
static uint16_t rc5_key[2*(20+1)] = {0};
#endif
#if CRYPTO_ALG == FF3
static struct keystruct rk;
static uint8_t ff3_key[16] = {0};
#endif

static uint8_t tweak[8] = {0};
static uint8_t hash[20];

struct prefix_table {
	int32_t prev_prefix;
	int32_t next_prefix;
	int32_t index;	/* or previous index */
};

struct nat_table {
	struct prefix_table *prefix_tbl;
	int32_t *idx_tbl;	// Maps from index to prefix
};

struct nat_table *nat_tbl[NB_SOCKETS];
int32_t MAX_IDX = -1;
int32_t MAX_PREFIX = -1;

/*inline void ip_checksum (const void *);*/
/*inline void udp_checksum (const void *);*/
/*inline void tcp_checksum (const void *);*/
inline uint32_t idx_to_ip (struct nat_table *, int32_t idx);
inline uint32_t ip_to_idx (struct nat_table *, uint32_t addr);
void load_rtbl (struct prefix_table *, int32_t *idx_table);

void load_rtbl (struct prefix_table *t, int32_t *idx_table) {
	char prefix[20];
	char *ptr, *pos;
	uint8_t mask = 32;
	int32_t prev_pos = 1;
	int32_t prev_p=-1;
	int32_t p=-1;
	int32_t idx;

	int32_t prev_idx = -1;
	uint8_t a,b,c,d;
	uint32_t addr;
	int32_t i;
	int32_t *next_prefix_ptr = NULL;
	FILE *fp = fopen (rtbl_file, "r");
	if (!fp) {
		printf ("Error: Cannot open file %s\n", rtbl_file);
		exit (-1);
	}

	while (fscanf (fp, "%s %d\n", prefix, &idx) != EOF) {
		ptr = prefix;

		pos = strstr (ptr, "/");
		mask = atoi (pos + 1);
		*pos = 0;

		pos = strstr (ptr, ".");
		*pos++ = 0;
		a = atoi (ptr);

		ptr = pos;
		pos = strstr (ptr, ".");
		*pos++ = 0;
		b = atoi (ptr);

		ptr = pos;
		pos = strstr (ptr, ".");
		*pos++ = 0;
		c = atoi (ptr);

		ptr = pos;
		d = atoi (ptr);

		addr = IPv4 (a,b,c,d);

		if (mask == 8)
			p = addr >> 24;
		else if (mask == 16)
			p = addr >> 16;
		else if (mask == 24)
			p = addr >> 8;
#if DPDK
		else {
			RTE_LOG (ERR, NAT, "invalid prefix len %d\n", mask);
			continue;
		}
#else
		else {
			printf ("[ERROR] invalid prefix len %d\n", mask);
			continue;
		}
#endif

		if (idx == 0) {
			idx_table[0] = p;
		}
		else if (idx/(65536 * 256) != prev_idx/(65536 * 256)) {
			idx_table[idx/(65536*256)] = p;
		}
		else if (idx/65536 != prev_idx/65536) {
			idx_table[idx/65536] = p;
		}

		if (next_prefix_ptr)
			*next_prefix_ptr = p;

		for (i = prev_pos; i < p; i++) {
			t[i].prev_prefix = prev_p;
			t[i].next_prefix = p;
			t[i].index = prev_idx;
		}

		t[p].prev_prefix = p;
		t[p].index = idx;
		next_prefix_ptr = &t[p].next_prefix;

		prev_idx = idx;
		prev_p = p;
		prev_pos = p + 1;
	}

	t[p].next_prefix = p+1;
	t[p+1].index = t[p].index + (1<<(32-mask));

	MAX_IDX = idx + (1<<(32-mask));
	MAX_PREFIX = p + 1;
}

void setup_nat_table (const int socketid) {
#if DPDK
	nat_tbl[socketid] = (struct nat_table *)rte_zmalloc_socket (NULL,
												sizeof (struct nat_table),
												RTE_CACHE_LINE_SIZE, socketid);
	if (!nat_tbl[socketid]) {
		RTE_LOG (ERR, NAT, "nat_tbl allocation failed\n");
		return;
	}

	nat_tbl[socketid]->prefix_tbl = (struct prefix_table *)rte_zmalloc_socket (NULL,
																(1<<24) * sizeof (struct prefix_table),
																RTE_CACHE_LINE_SIZE, socketid);
	if (!nat_tbl[socketid]->prefix_tbl) {
		RTE_LOG (ERR, NAT, "prefix_tbl allocation failed\n");
		/*free (nat_tbl[socketid]);*/
		return;
	}

	nat_tbl[socketid]->idx_tbl = (int32_t *)rte_zmalloc_socket (NULL,
												2000 * 4,
												RTE_CACHE_LINE_SIZE, socketid);
	if (!nat_tbl[socketid]->idx_tbl) {
		printf ("[ERROR] memory allocation failed\n");
		/*free (nat_tbl[socketid].prefix_tbl);*/
		/*free (nat_tbl[socketid]);*/
		return;
	}
#else
	nat_tbl[socketid] = (struct nat_table *)calloc (1, sizeof (struct nat_table));
    if (!nat_tbl[socketid]) {
        printf ("nat_tbl allocation failed\n");
        return;
    }

    nat_tbl[socketid]->prefix_tbl = (struct prefix_table *)calloc (1<<24, sizeof (struct prefix_table));
    if (!nat_tbl[socketid]->prefix_tbl) {
        printf ("prefix_tbl allocation failed\n");
		free (nat_tbl[socketid]);
        return;
    }

    nat_tbl[socketid]->idx_tbl = (int32_t *)calloc (2000, 4);
    if (!nat_tbl[socketid]->idx_tbl) {
        printf ("[ERROR] memory allocation failed\n");
		free (nat_tbl[socketid]->prefix_tbl);
		free (nat_tbl[socketid]);
        return;
    }
#endif

	load_rtbl (nat_tbl[socketid]->prefix_tbl, nat_tbl[socketid]->idx_tbl);

#if CRYPTO_ALG == FF3
	init_key (&rk, ff3_key);
#endif
#if CRYPTO_ALG == CHACHA20
	nat_setkey_chacha20 (&chacha_ctx, chacha_key, 256, chacha_iv, 32);
#endif

	sha1 (tweak, 8, hash);
}

void destroy_nat_table (const int socketid) {
	free (nat_tbl[socketid]->prefix_tbl);
	free (nat_tbl[socketid]->idx_tbl);
	free (nat_tbl[socketid]);
	nat_tbl[socketid] = NULL;
#if CRYPTO_ALG == FF3
	destroy_key (&rk);
#endif
}

void *get_nat_table (const int socketid) {
	return nat_tbl[socketid];
}

#if !DPDK
uint32_t idx_to_ip_test (int32_t idx) {
	return idx_to_ip (nat_tbl[0], idx);
}
#endif

/*
	No safety check is performed.
	If idx is larger than MAX_IDX, then it will become an infinite loop.
*/
inline uint32_t idx_to_ip (struct nat_table *nat, int32_t idx) {
	struct prefix_table *t = nat->prefix_tbl;
	int32_t *idx_table = nat->idx_tbl;
	int32_t prefix;

	prefix = idx_table [idx >> 24];
	if (prefix < (1<<8)) {
		return htonl ((prefix << 24) | (idx & 0xffffff));
	}

	prefix = idx_table [idx >> 16];
	if (prefix < (1<<16)) {
		return htonl ((prefix << 16) | (idx & 0xffff));
	}

	while (t[t[prefix].next_prefix].index <= idx) prefix = t[prefix].next_prefix;

	return htonl ((prefix << 8) | (idx & 0xff));
}

inline uint32_t ip_to_idx (struct nat_table *nat, uint32_t addr) {
	struct prefix_table *t = nat->prefix_tbl;
	int32_t p8, h8, p16, h16, p24, h24;

#ifdef DEBUG
	printf ("[%s] addr (%s)\n", __func__, inet_ntoa (*(struct in_addr *)&addr));
#endif

	addr = ntohl (addr);

	p24 = addr >> 8;
	h24 = addr & 0xff;
	if (p24 < MAX_PREFIX && t[p24].prev_prefix == p24) {
#ifdef DEBUG
		printf ("p24: idx (%d)\n", t[p24].index + h24);
#endif
		return t[p24].index + h24;
	}

	p16 = addr >> 16;
	h16 = addr & 0xffff;
	if (t[p16].prev_prefix == p16) {
#ifdef DEBUG
		printf ("p16: idx (%d)\n", t[p16].index + h16);
#endif
		return t[p16].index + h16;
	}

	p8 = addr >> 24;
	h8 = addr & 0xffffff;
	if (t[p8].prev_prefix == p8) {
#ifdef DEBUG
		printf ("p8: idx (%d)\n", t[p8].index + h8);
#endif
		return t[p8].index + h8;
	}

	return 0;
}

inline int process_outgoing_pkt (void *t, void *ipv4_hdr) {
	ff3_msg_t input, output;
	uint32_t idx;
	struct ipv4_5tuple_host *tuple;
	/*struct in_addr a;*/

#ifdef DEBUG
	printf ("[%s]\n", __func__);
#endif

#if DPDK
	tuple = (struct ipv4_5tuple_host *) ((uint8_t *)ipv4_hdr + offsetof (struct ipv4_hdr, time_to_live));
#else
	tuple = (struct ipv4_5tuple_host *) ((uint8_t *)ipv4_hdr + offsetof (struct iphdr, ttl));
#endif

	input.port = tuple->sport;
	input.host = (ntohl (tuple->saddr) & HOST_MASK);

#ifdef DEBUG
	int64_t *ptr64 = (int64_t *)&input;
	printf ("init: 0x%016" PRIx64 "\n", *ptr64);
#endif

#if CRYPTO_ALG == CHACHA20 || CRYPTO_ALG == FF3
	input.port ^= tuple->dport;
	input.host ^= (ntohl (tuple->daddr) & HOST_MASK);
#endif

#ifdef DEBUG
	printf ("pt: 0x%016" PRIx64 "\n", *ptr64);
#endif

#if CRYPTO_ALG == CHACHA20
	nat_encrypt_chacha20 (&chacha_ctx, (uint8_t *)&input, BLOCK_LEN, (uint8_t *)&output);
#elif CRYPTO_ALG == FF3
	nat_encrypt_ff3 ((uint8_t *)&input, BLOCK_LEN, tweak, &rk, (uint8_t *)&output);
#elif CRYPTO_ALG == RC5
	uint16_t *tweakptr = (uint16_t *)tweak;
	*tweakptr = tuple->dport;
	*(tweakptr + 1) = (tuple->daddr & HOST_MASK);
	sha1 (tweak, 8, hash);

	nat_encrypt_rc5 ((uint32_t *)&input, rc5_key, hash, (uint32_t *)&output);
#endif

#ifdef DEBUG
	ptr64 = (int64_t *)&output;
	printf ("ct: 0x%016" PRIx64 "\n", *ptr64);
#endif

	idx = output.host;
#ifdef DEBUG
	printf ("host_idx (%d)\n", idx);
#endif
	tuple->sport = output.port;
	tuple->saddr = idx_to_ip (t, idx);
	/*a.s_addr = tuple->saddr;*/
	/*printf ("host_idx (%d), [%s:%d]\n", idx, inet_ntoa (a), ntohs (tuple->sport));*/

#if CHECKSUM
#if DPDK
	if (*((uint8_t *)ipv4_hdr + offsetof (struct ipv4_hdr, next_proto_id)) == 6)
		tcp_checksum (ipv4_hdr);
	else
		udp_checksum (ipv4_hdr);
#else
	if (*((uint8_t *)ipv4_hdr + offsetof (struct iphdr, protocol)) == 6)
		tcp_checksum (ipv4_hdr);
	else
		udp_checksum (ipv4_hdr);
#endif

	ip_checksum (ipv4_hdr);
#endif

	return 0;
}

inline int process_incoming_pkt (void *t, void *ipv4_hdr) {
	ff3_msg_t input, output;
	uint32_t idx, host;
	struct ipv4_5tuple_host *tuple;

#ifdef DEBUG
	printf ("[%s]\n", __func__);
#endif

#if DPDK
	tuple = (struct ipv4_5tuple_host *) ((uint8_t *)ipv4_hdr + offsetof (struct ipv4_hdr, time_to_live));
#else
	tuple = (struct ipv4_5tuple_host *) ((uint8_t *)ipv4_hdr + offsetof (struct iphdr, ttl));
#endif

	input.port = tuple->dport;
	idx = ip_to_idx (t, tuple->daddr);
	input.host = idx;

#ifdef DEBUG
	int64_t *ptr64 = (int64_t *)&input;
	printf ("ct: 0x%016" PRIx64 "\n", *ptr64);
#endif

#if CRYPTO_ALG == FF3
	nat_decrypt_ff3 ((uint8_t *)&input, BLOCK_LEN, tweak, &rk, (uint8_t *)&output);
#elif CRYPTO_ALG == CHACHA20
	nat_decrypt_chacha20 (&chacha_ctx, (uint8_t *)&input, BLOCK_LEN, (uint8_t *)&output);
#else
	uint16_t *tweakptr = (uint16_t *)tweak;
    *tweakptr = tuple->sport;
    *(tweakptr + 1) = (tuple->saddr & HOST_MASK);
    sha1 (tweak, 8, hash);
	nat_decrypt_rc5 ((uint32_t *)&input, rc5_key, hash, (uint32_t *)&output);
#endif

#ifdef DEBUG
	ptr64 = (int64_t *)&output;
	printf ("pt: 0x%016" PRIx64 "\n", *ptr64);
#endif

#if CRYPTO_ALG == CHACHA20 || CRYPTO_ALG == FF3
	output.port ^= tuple->sport;
	output.host ^= (ntohl (tuple->saddr) & HOST_MASK);
#endif

#ifdef DEBUG
	printf ("final: 0x%016" PRIx64 "\n", *ptr64);
#endif

	host = output.host;
#ifdef DEBUG
	printf ("host_addr (%d)\n", host);
#endif
	tuple->daddr = htonl (0x0A000000 | host);
	tuple->dport = output.port;

#if CHECKSUM
#if DPDK
	if (*((uint8_t *)ipv4_hdr + offsetof (struct ipv4_hdr, next_proto_id)) == 6)
		tcp_checksum (ipv4_hdr);
	else
		udp_checksum (ipv4_hdr);
#else
	if (*((uint8_t *)ipv4_hdr + offsetof (struct iphdr, protocol)) == 6)
		tcp_checksum (ipv4_hdr);
	else
		udp_checksum (ipv4_hdr);
#endif

	ip_checksum (ipv4_hdr);
#endif

	return 0;
}

#if 0
inline void ip_checksum (const void *iphdr) {
	const uint16_t *buf;
	uint32_t sum;
	size_t len;
	uint16_t *csum;

#if DPDK
	len = ntohs (*((uint8_t *)iphdr + offsetof (struct ipv4_hdr, total_length)));
	csum = (uint16_t *)((uint8_t *)iphdr + offsetof (struct ipv4_hdr, hdr_checksum));
#else
	len = ntohs (*((uint8_t *)iphdr + offsetof (struct iphdr, tot_len)));
	csum = (uint16_t *)((uint8_t *)iphdr + offsetof (struct iphdr, check));
#endif
	buf = (uint16_t *)iphdr;
	*csum = 0;

	// Calculate the sum                                            //
	sum = 0;
	while (len > 1) {
		sum += *buf++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if ( len & 1 )
		// Add the padding if the packet lenght is odd          //
		sum += *((uint8_t *)buf);

	// Add the carries                                              //
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Return the one's complement of sum                           //
	*csum = (uint16_t)(~sum);
}

inline void tcp_checksum (const void *iphdr) {
	const uint16_t *buf;
	uint16_t *ip_src, *ip_dst;
	uint32_t sum;
	size_t length, len;
	uint16_t *csum;

#if DPDK
	ip_src = (uint16_t *)((uint8_t *)iphdr + offsetof (struct ipv4_hdr, src_addr));
	ip_dst = (uint16_t *)((uint8_t *)iphdr + offsetof (struct ipv4_hdr, dst_addr));
	len = ntohs (*((uint8_t *)iphdr + offsetof (struct ipv4_hdr, total_length))) - 20;
	csum = (uint16_t *)((uint8_t *)iphdr + 20 + offsetof (struct tcp_hdr, cksum));
#else
	ip_src = (uint16_t *)((uint8_t *)iphdr + offsetof (struct iphdr, saddr));
	ip_dst = (uint16_t *)((uint8_t *)iphdr + offsetof (struct iphdr, daddr));
	len = ntohs (*((uint8_t *)iphdr + offsetof (struct iphdr, tot_len))) - 20;
	csum = (uint16_t *)((uint8_t *)iphdr + 20 + offsetof (struct tcphdr, check));
#endif
	buf = (uint16_t *)((uint8_t *)iphdr + 20);
	length = len;
	*csum = 0;

	// Calculate the sum                                            //
	sum = 0;
	while (len > 1) {
		sum += *buf++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if ( len & 1 )
		// Add the padding if the packet lenght is odd          //
		sum += *((uint8_t *)buf);

	// Add the pseudo-header                                        //
	sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *ip_dst;
	sum += htons(IPPROTO_TCP);
	sum += htons(length);

	// Add the carries                                              //
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Return the one's complement of sum                           //
	*csum = (uint16_t)(~sum);
}

inline void udp_checksum (const void *iphdr) {
	const uint16_t *buf;
	uint16_t *ip_src, *ip_dst;
	uint32_t sum;
	size_t length, len;
	uint16_t *csum;

#if DPDK
	ip_src = (uint16_t *)((uint8_t *)iphdr + offsetof (struct ipv4_hdr, src_addr));
	ip_dst = (uint16_t *)((uint8_t *)iphdr + offsetof (struct ipv4_hdr, dst_addr));
	len = ntohs (*((uint16_t *)((uint8_t *)iphdr + 20 + offsetof (struct udp_hdr, dgram_len))));
	csum = (uint16_t *)((uint8_t *)iphdr + 20 + offsetof (struct udp_hdr, dgram_cksum));
#else
	ip_src = (uint16_t *)((uint8_t *)iphdr + offsetof (struct iphdr, saddr));
	ip_dst = (uint16_t *)((uint8_t *)iphdr + offsetof (struct iphdr, daddr));
	len = ntohs (*((uint16_t *)((uint8_t *)iphdr + 20 + offsetof (struct udphdr, len))));
	csum = (uint16_t *)((uint8_t *)iphdr + 20 + offsetof (struct udphdr, check));
#endif
	buf = (uint16_t *)((uint8_t *)iphdr + 20);
	length = len;
	*csum = 0;

	// Calculate the sum                                            //
	sum = 0;
	while (len > 1) {
		sum += *buf++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if ( len & 1 )
		// Add the padding if the packet lenght is odd          //
		sum += *((uint8_t *)buf);

	// Add the pseudo-header                                        //
	sum += *(ip_src++);
	sum += *ip_src;

	sum += *(ip_dst++);
	sum += *ip_dst;

	sum += htons(IPPROTO_UDP);
	sum += htons(length);

	// Add the carries                                              //
	while (sum >> 16)
	sum = (sum & 0xFFFF) + (sum >> 16);

	// Return the one's complement of sum                           //
	*csum = (uint16_t)(~sum);
}
#endif
