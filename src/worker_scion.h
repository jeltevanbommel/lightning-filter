
#ifndef LF_WORKER_SCION_H
#define LF_WORKER_SCION_H

#include <inttypes.h>

#include <stdint.h>

#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "config.h"
#include "configmanager.h"
#include "lib/scion/scion.h"
#include "lib/utils/packet.h"
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "config.h"
// #include "distributor.h"
// #include "keymanager.h"
#include "lf.h"
#include "lib/crypto/crypto.h"
#include "lib/log/log.h"
// #include "lib/time/time.h"
// #include "ratelimiter.h"
// #include "worker.h"

struct scion_mac_input {
	// scion authenticator option metadata
	uint8_t hdr_len;
	uint8_t payload_protocol;
	uint16_t payload_length;
	uint8_t algorithm;
	uint8_t time_stamp[3];
	uint8_t reserved;
	uint8_t sequence_number[3];

	// hash
	uint8_t hash[20];
} __attribute__((__packed__));

#define SPAO_GET_MAC_INPUT(spao_hdr) \
	((struct scion_mac_input *)((uint8_t *)(spao_hdr) + 2))

/**
 * Structure to store information of a parsed inter-AS packet, which is supposed
 * to be handled by LightningFilter.
 */
struct parsed_pkt {
	struct rte_ether_hdr *ether_hdr;
	union {
		void *l3_hdr;
		struct rte_ipv4_hdr *ipv4_hdr;
		struct rte_ipv6_hdr *ipv6_hdr;
	};
	struct rte_udp_hdr *udp_hdr;

	struct scion_cmn_hdr *scion_cmn_hdr;

	struct scion_addr_ia_hdr *scion_addr_ia_hdr;
	uint32_t scion_addr_hdr_len;

	void *scion_path_hdr;
	uint32_t scion_path_hdr_len;
	uint32_t path_timestamp;

	/* Offset to the memory after the SCION path,
	 * i.e., to the payload or SCION extension headers. */
	unsigned int offset;

	struct scion_pao *spao_hdr;
};

/**
 * Structure to store SPAO data, as well as, payload information.
 * Furthermore, this structure also acts as storage for values that are
 * temporarily overwritten for the MAC computation.
 */
struct parsed_spao {
	/* Pointer to the SPAO header. */
	struct scion_packet_authenticator_opt *spao_hdr;

	/* Protocol of the next layer */
	uint8_t payload_protocol;
	/* Offset to the next layer */
	unsigned int payload_offset;
	/* Length of the next layer. */
	unsigned int payload_length;

	/*
	 * Temporary storage for overwritten values.
	 */
	uint8_t hdr_len_old;
	uint8_t upper_layer_protocol_old;
	uint16_t upper_layer_length_old;
};


int
parse_pkt(struct rte_mbuf *m, unsigned int offset,
		struct parsed_pkt *parsed_pkt);


int
get_lf_spao_hdr(struct rte_mbuf *m, struct parsed_pkt *parsed_pkt,
		struct parsed_spao *parsed_spao, struct lf_pkt_data *pkt_data);


static inline int
hash_cmn_hdr(struct lf_crypto_hash_ctx *ctx,
		struct scion_cmn_hdr *scion_cmn_hdr)
{
	uint8_t ecn_old;

	ecn_old = scion_cmn_hdr->version_qos_flowid[1];
	scion_cmn_hdr->version_qos_flowid[1] &= 0xCF; // 0b11001111;
	lf_crypto_hash_update(ctx, (uint8_t *)scion_cmn_hdr, 4);
	lf_crypto_hash_update(ctx, (uint8_t *)scion_cmn_hdr + 8, 4);
	scion_cmn_hdr->version_qos_flowid[1] = ecn_old;
	return 0;
}

static inline int
hash_path_hdr(struct lf_crypto_hash_ctx *ctx, void *path_hdr,
		uint8_t path_type, uint32_t path_header_len)
{
	switch (path_type) {
	case SCION_PATH_TYPE_EMPTY:
		/* nothing to do here */
		break;
	case SCION_PATH_TYPE_SCION: {
		if (unlikely(sizeof(struct scion_path_meta_hdr) > path_header_len)) {
			LF_WORKER_LOG_DP(NOTICE,
					"Invalid SCION packet: path header type "
					"inconsistent with expected path header length.\n");
			return -1;
		}

		struct scion_path_meta_hdr *scion_path_meta_hdr =
				(struct scion_path_meta_hdr *)path_hdr;

		uint32_t seg_len[3];
		seg_len[0] = ((scion_path_meta_hdr->seg_len[0] & 0x03) << 4) |
		             ((scion_path_meta_hdr->seg_len[1] & 0xF0) >> 4);
		seg_len[1] = ((scion_path_meta_hdr->seg_len[1] & 0x0F) << 2) |
		             ((scion_path_meta_hdr->seg_len[2] & 0xC0) >> 6);
		seg_len[2] = ((scion_path_meta_hdr->seg_len[2] & 0x3F));

		if (unlikely(seg_len[0] + seg_len[1] + seg_len[2] > 64)) {
			LF_WORKER_LOG_DP(NOTICE, "Invalid SCION packet: path header hop "
									 "field number exceeds 64.\n");
			return -1;
		}

		uint32_t actual_path_header_len =
				sizeof *scion_path_meta_hdr +
				(seg_len[0] ? SCION_PATH_INFOFIELD_SIZE +
										seg_len[0] * SCION_PATH_HOPFIELD_SIZE
							: 0) +
				(seg_len[1] ? SCION_PATH_INFOFIELD_SIZE +
										seg_len[1] * SCION_PATH_HOPFIELD_SIZE
							: 0) +
				(seg_len[2] ? SCION_PATH_INFOFIELD_SIZE +
										seg_len[2] * SCION_PATH_HOPFIELD_SIZE
							: 0);
		if (unlikely(actual_path_header_len != path_header_len)) {
			LF_WORKER_LOG_DP(NOTICE,
					"Invalid SCION packet: SCION path header length "
					"inconsistent with path header length.\n");
			return -1;
		}

		/* PathMeta Header (with CurrINF, CurrHF zeroed) */
		uint8_t curr_old = scion_path_meta_hdr->curr_inf_hf;
		scion_path_meta_hdr->curr_inf_hf = 0;

		/* InfoField Header (with SegID zeroed) */
		uint16_t seg_id_old[3];
		struct scion_path_info_hdr *info_field =
				(struct scion_path_info_hdr *)(scion_path_meta_hdr + 1);
		for (size_t i = 0; i < 3; ++i) {
			if (seg_len[i] != 0) {
				seg_id_old[i] = info_field->seg_id;
				info_field->seg_id = 0;
				info_field += 1;
			}
		}

		/* HopField Header (with router alerts zeroed) */
		struct scion_path_hop_hdr *hop_field =
				(struct scion_path_hop_hdr *)info_field;
		uint8_t router_alerts_old[64];
		for (size_t i = 0; i < seg_len[0] + seg_len[1] + seg_len[2]; ++i) {
			router_alerts_old[i] = hop_field->rie;
			hop_field->rie &= 0xFC; // 0b11111100;
			hop_field += 1;
		}

		lf_crypto_hash_update(ctx,
				(uint8_t *)path_hdr, path_header_len);

		/* PathMeta Header reset */
		scion_path_meta_hdr->curr_inf_hf = curr_old;

		/* InfoField Header reset */
		info_field = (struct scion_path_info_hdr *)(scion_path_meta_hdr + 1);
		for (size_t i = 0; i < 3; ++i) {
			if (seg_len[i] != 0) {
				info_field->seg_id = seg_id_old[i];
				info_field += 1;
			}
		}

		/* HopField Header reset */
		hop_field = (struct scion_path_hop_hdr *)info_field;
		for (size_t i = 0; i < seg_len[0] + seg_len[1] + seg_len[2]; ++i) {
			hop_field->rie = router_alerts_old[i];
			hop_field += 1;
		}
		break;
	}
	case SCION_PATH_TYPE_ONEHOP: {
		if (unlikely(SCION_PATH_INFOFIELD_SIZE + 2 * SCION_PATH_HOPFIELD_SIZE >
					 path_header_len)) {
			LF_WORKER_LOG_DP(NOTICE, "Invalid SCION packet: path header type "
									 "inconsistent with header length.\n");
			return -1;
		}
		struct scion_path_info_hdr *scion_path_info_hdr =
				(struct scion_path_info_hdr *)path_hdr;

		/* add info field and first hop field (with router alert flags zeroed)
		 */
		struct scion_path_hop_hdr *hop_field_1 =
				(struct scion_path_hop_hdr *)(scion_path_info_hdr + 1);
		uint8_t router_alerts_old = hop_field_1->rie;
		hop_field_1->rie &= 0xFC; // 0b11111100;
		lf_crypto_hash_update(ctx,
				(uint8_t *)path_hdr,
				SCION_PATH_INFOFIELD_SIZE + SCION_PATH_HOPFIELD_SIZE);
		hop_field_1->rie = router_alerts_old;

		/* add second hop field (with everything zeroed) */
		uint8_t hop_field_zeroed[SCION_PATH_HOPFIELD_SIZE] = { 0 };
		lf_crypto_hash_update(ctx,
				hop_field_zeroed, SCION_PATH_HOPFIELD_SIZE);
		break;
	}
	default:
		LF_WORKER_LOG_DP(NOTICE, "Unknown SCION path type %u.\n", path_type);
		return -1;
		break;
	}

	return 0;
}

/**
 * Assume that the complete SCION header (limited through its size defined
 * in the cmn header) can be accessed in the same mbuf.
 * @return 0 if succeeds.
 */
static inline int
compute_pkt_hash(struct lf_worker_context *worker_context, struct rte_mbuf *m,
		struct parsed_pkt *parsed_pkt, struct parsed_spao *parsed_spao,
		uint8_t hash[LF_CRYPTO_HASH_LENGTH])
{
	int res;
	uint8_t *payload;

	/* hash common header */
	res = hash_cmn_hdr(&worker_context->crypto_hash_ctx,
			parsed_pkt->scion_cmn_hdr);
	if (unlikely(res != 0)) {
		return res;
	}
	/* hash path header */
	res = hash_path_hdr(&worker_context->crypto_hash_ctx, parsed_pkt->scion_path_hdr,
			parsed_pkt->scion_cmn_hdr->path_type,
			parsed_pkt->scion_path_hdr_len);
	if (unlikely(res != 0)) {
		return res;
	}

	/* hash payload */
	if (unlikely(parsed_spao->payload_offset + parsed_spao->payload_length >
				 m->data_len)) {
		LF_WORKER_LOG_DP(NOTICE,
				"Not yet implemented: SCION payload exceeds "
				"first buffer segment (offset = %d, length = %d, segment = "
				"%d).\n",
				parsed_spao->payload_offset, parsed_spao->payload_length,
				m->data_len);
		return -1;
	}
	payload =
			rte_pktmbuf_mtod_offset(m, uint8_t *, parsed_spao->payload_offset);
            
	(void)lf_crypto_hash_update(&worker_context->crypto_hash_ctx, payload,
			parsed_spao->payload_length);

	LF_WORKER_LOG_DP(DEBUG, "Finalize hash\n");
	(void)lf_crypto_hash_final(&worker_context->crypto_hash_ctx, hash);

	return 0;
}

#endif /* LF_WORKER_SCION_H */
