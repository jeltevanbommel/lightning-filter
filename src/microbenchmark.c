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



#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_rcu_qsbr.h>
#include <rte_spinlock.h>
#include <rte_telemetry.h>

#define DATA_SIZE 1500
size_t payload_1_len = 12;
uint8_t payload_1[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
uint8_t payload_2[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };


struct message {
    char data[DATA_SIZE];
};

int
main(int argc, char **argv)
{
	int ret;
	unsigned lcore_id;
    unsigned port = 0;
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	unsigned lcore_id;
	lcore_id = rte_lcore_id();

	struct rte_mbuf *fake_mbuf = NULL;
	uint16_t socket_id = rte_lcore_to_socket_id(lcore_id);

    // Initialize an mbuf pool
	struct rte_mempool *mb_pool = rte_pktmbuf_pool_create("dummy_pool", 2560, LF_SETUP_MEMPOOL_CACHE_SIZE,
			LF_SETUP_METADATA_SIZE, LF_SETUP_BUF_SIZE, socket_id);

    // Create dummy payload:
    struct message obj;
    int count = 0;
    int k = 0;
    for (count = 0; count < DATA_SIZE; count++){
        obj.data[count] = (char)(97 + (k++));
        if (k == 26)
            k = 0;
    }

    // Allocate an mbuf:
	struct rte_mbuf *mbuf_ptr = rte_pktmbuf_alloc(mbuf_pool);
	mbuf_ptr->data_len = sizeof(struct message) + sizeof(struct rte_ether_hdr);
	mbuf_ptr->pkt_len = mbuf_ptr->data_len;

    // Prepare packet contents:
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf_ptr, struct rte_ether_hdr *);
    rte_eth_macaddr_get(port, &eth_hdr->d_addr);
    rte_eth_macaddr_get(port, &eth_hdr->s_addr);
    eth_hdr->ether_type = 0x01;

    char* data;
    data = rte_pktmbuf_append(mbuf_ptr, sizeof(struct message));
    if (data != NULL)
        rte_memcpy(data, &obj, sizeof(struct message));

    rte_pktmbuf_dump(stdout, mbuf_ptr, mbuf_ptr->data_len);
	// struct parsed_spao parsed_spao;
	// struct lf_pkt_data pkt_data;

	// res = get_lf_spao_hdr(m, parsed_pkt, &parsed_spao, &pkt_data);
	
	// int res;
	// res = parse_pkt(m, 0, parsed_pkt);
	
	// uint8_t hash_1[20];
	// uint8_t hash_2[20];
	// uint8_t hash[LF_CRYPTO_HASH_LENGTH];
	// struct lf_crypto_hash_ctx hash_ctx;

	// res = lf_crypto_hash_ctx_init(&hash_ctx);

	// res = hash_cmn_hdr(&hash_ctx,
	// 		parsed_pkt->scion_cmn_hdr);
	// if (unlikely(res != 0)) {
	// 	return res;
	// }

	// /* hash path header */
	// res = hash_path_hdr(&hash_ctx, parsed_pkt->scion_path_hdr,
	// 		parsed_pkt->scion_cmn_hdr->path_type,
	// 		parsed_pkt->scion_path_hdr_len);
	// if (unlikely(res != 0)) {
	// 	return res;
	// }

	// /* hash payload */
	// if (unlikely(parsed_spao->payload_offset + parsed_spao->payload_length >
	// 			 m->data_len)) {
	// 	LF_WORKER_LOG_DP(NOTICE,
	// 			"Not yet implemented: SCION payload exceeds "
	// 			"first buffer segment (offset = %d, length = %d, segment = "
	// 			"%d).\n",
	// 			parsed_spao->payload_offset, parsed_spao->payload_length,
	// 			m->data_len);
	// 	return -1;
	// }
	// payload =
	// 		rte_pktmbuf_mtod_offset(m, uint8_t *, parsed_spao->payload_offset);
	// (void)lf_crypto_hash_update(&hash_ctx, payload,
	// 		parsed_spao->payload_length);

	// // LF_WORKER_LOG_DP(DEBUG, "Finalize hash\n");
	// (void)lf_crypto_hash_final(&hash_ctx, hash);

	return 0;

}
