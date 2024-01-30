/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <rte_config.h>
#include <rte_mbuf_core.h>
#include <arpa/inet.h>
#include "setup.h"

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_rcu_qsbr.h>
#include <rte_cycles.h>
#include <rte_spinlock.h>
#include <rte_mbuf.h>
#include <rte_telemetry.h>
#include "worker_scion.h"

#define LF_SETUP_MEMPOOL_CACHE_SIZE 256
#define LF_SETUP_METADATA_SIZE      0
#if LF_JUMBO_FRAME
#define LF_SETUP_BUF_SIZE JUMBO_FRAME_MAX_SIZE
#else
#define LF_SETUP_BUF_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#endif
#define DATA_SIZE 1500

/* lcore assignemnts */
uint16_t lf_nb_workers;
uint16_t lf_worker_lcores[RTE_MAX_LCORE];
uint16_t lf_keymanager_lcore;
uint16_t lf_nb_distributors;


/**
 * Global force quit flag.
 */
volatile bool lf_force_quit = false;


int lf_logtype;
void
lf_log(uint32_t level, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	(void)rte_vlog(level, lf_logtype, format, args);
	va_end(args);
}

void
lf_print(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	(void)vprintf(format, args);
	va_end(args);
}

struct message {
	char hdr_part1[34];
	uint16_t payload_len;
	char hdr_part2[148];
    unsigned char data[DATA_SIZE];
};

const char HDR_1[] = {0x45, 0x00, 0x00, 0xc8, 0x36, 0x7e, 0x40, 0x00, 0x40, 0x11, 0xea, 0xb4, 0x0a, 0xf8, 0x01, 0x01, 0x0a, 0xf8, 0x02, 0x02, 0x79, 0x24, 0x75, 0x59, 0x00, 0xb4, 0x19, 0xb8, 0x00, 0x00, 0x00, 0x01, 0xc9, 0x1a};
const char HDR_2[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00, 0x01, 0x11, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00, 0x01, 0x12, 0x0a, 0xf8, 0x02, 0x02, 0x0a, 0xf8, 0x05, 0x02, 0x43, 0x00, 0x20, 0x80, 0x00, 0x00, 0x74, 0xe2, 0x62, 0xa7, 0x3c, 0xd8, 0x01, 0x00, 0xdf, 0xda, 0x62, 0xa7, 0x3c, 0xd8, 0x00, 0x3f, 0x00, 0x01, 0x00, 0x00, 0x26, 0x57, 0x97, 0x2c, 0x54, 0xbd, 0x00, 0x3f, 0x00, 0x00, 0x00, 0x02, 0x46, 0xd0, 0x0a, 0xcb, 0x0a, 0xe7, 0x00, 0x3f, 0x00, 0x00, 0x00, 0x01, 0xb5, 0x71, 0x07, 0x3b, 0xa3, 0xe3, 0x00, 0x3f, 0x00, 0x29, 0x00, 0x00, 0xcc, 0x4f, 0x72, 0xae, 0x18, 0x74, 0xca, 0x0c, 0x02, 0x30, 0x00, 0x06, 0x00, 0x01, 0x01, 0x00, 0xb9, 0x84, 0x00, 0x2c, 0x54, 0xbd, 0xd5, 0x11, 0xbb, 0x28, 0xa8, 0xb5, 0xce, 0x25, 0x52, 0xb5, 0x2b, 0x8e, 0x08, 0x3b, 0xd0, 0xa9, 0x15, 0x59, 0xdd, 0xba, 0xac, 0x4c, 0xb9, 0x8d, 0xe4, 0x1d, 0x84, 0x37, 0x22, 0x8a, 0x2b, 0xac, 0xe3, 0xe7, 0x93, 0xca};
int
main(int argc, char **argv)
{
	int ret;
	unsigned lcore_id;
    unsigned port = 0;
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	lcore_id = rte_lcore_id();

	uint16_t socket_id = rte_lcore_to_socket_id(lcore_id);

    // Initialize an mbuf pool
	struct rte_mempool *mb_pool = rte_pktmbuf_pool_create("dummy_pool", 64060, LF_SETUP_MEMPOOL_CACHE_SIZE,
			LF_SETUP_METADATA_SIZE, LF_SETUP_BUF_SIZE, socket_id);

    // Create dummy payload:
    struct message obj;
    int count = 0;
	memcpy(obj.hdr_part1, HDR_1, 34);
	memcpy(obj.hdr_part2, &HDR_2, 148);
	obj.payload_len = ntohs(DATA_SIZE + 52); //52 for the extension header, it is counted as payload.

	srand(42);
    for (count = 0; count < DATA_SIZE; count++){
		obj.data[count] = rand()%256;
    }

    // Allocate an mbuf:
	struct rte_mbuf *mbuf_ptr = rte_pktmbuf_alloc(mb_pool);
	mbuf_ptr->data_len = sizeof(struct message) + sizeof(struct rte_ether_hdr);
	mbuf_ptr->pkt_len = mbuf_ptr->data_len;

    // Prepare packet contents:
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf_ptr, struct rte_ether_hdr *);
    rte_eth_macaddr_get(port, &eth_hdr->dst_addr);
    rte_eth_macaddr_get(port, &eth_hdr->src_addr);
    eth_hdr->ether_type = 0x0008;

	struct message *data = rte_pktmbuf_mtod_offset(mbuf_ptr, struct message *,sizeof(struct rte_ether_hdr));
	rte_memcpy(data, &obj, sizeof(struct message));

	// Dump the packet as debug
    rte_pktmbuf_dump(stdout, mbuf_ptr, mbuf_ptr->data_len);
	
	// Setup lf related datastructures
	struct parsed_pkt parsed_pkt;
	int res;
	res = parse_pkt(mbuf_ptr, 0, &parsed_pkt);

	struct parsed_spao parsed_spao;
	struct lf_pkt_data pkt_data;

	res = get_lf_spao_hdr(mbuf_ptr, &parsed_pkt, &parsed_spao, &pkt_data);
	
	uint8_t hash[LF_CRYPTO_HASH_LENGTH];
	struct lf_crypto_hash_ctx hash_ctx;

	res = lf_crypto_hash_ctx_init(&hash_ctx);
	struct lf_worker_context worker_ctx;
	worker_ctx.crypto_hash_ctx = hash_ctx;


	res = compute_pkt_hash(&worker_ctx, mbuf_ptr, &parsed_pkt, &parsed_spao, hash);
	int i;
// for (i = 0; i < LF_CRYPTO_HASH_LENGTH; i++)
// {
//     if (i > 0) printf(" ");
//     printf("%02X", hash[i]);
// }
	uint64_t start = rte_rdtsc();
	#define iterations 10000000
	for( i = 0; i < iterations; i++){
		res = compute_pkt_hash(&worker_ctx, mbuf_ptr, &parsed_pkt, &parsed_spao, hash);
	}
	uint64_t end = rte_rdtsc();
    printf("size=%d, cycles=%" PRIu64 ", avg=%" PRIu64 "\n", DATA_SIZE, end-start, ((end-start)/iterations));
	(void)res;
	return 0;

}
