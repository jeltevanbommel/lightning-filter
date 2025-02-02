/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_KEYMANAGER_H
#define LF_KEYMANAGER_H

#include <inttypes.h>
#include <stdatomic.h>
#include <stdbool.h>

#include <rte_byteorder.h>
#include <rte_hash.h>
#include <rte_memcpy.h>
#include <rte_spinlock.h>

#include "config.h"
#include "lf.h"
#include "lib/crypto/crypto.h"
#include "lib/telemetry/counters.h"
#include "lib/time/time.h"

#include "lib/log/log.h"

/**
 * The key manager manages the storage and fetching of the required DRKeys.
 * It provides an interface for workers to query host-to-host keys efficiently.
 *
 * For the fetching, it depends on a DRKey fetcher module, which depends on the
 * deployment setup.
 */

#define LF_KEYMANAGER_INTERVAL 0.5 /* seconds */

/*
 * A DRKey is valid during a certain epoch defined by a starting and ending
 * point in time. During the transition between an old key and a new key, both
 * keys are valid. This transition period is defined by the
 * LF_DRKEY_GRACE_PERIOD, which extends the ending point of the old key by a
 * certain amount of time.
 */
#define LF_DRKEY_GRACE_PERIOD       (2 * LF_TIME_NS_IN_S) /* in nanoseconds */
#define LF_DRKEY_PREFETCHING_PERIOD (1 * LF_TIME_NS_IN_S) /* in nanoseconds */

/**
 * The key container wraps all information required to use a key.
 * A DRKeys validity is usually defined in seconds. Because the workers operate
 * with nanosecond timestamps, the validity timestamps are also stored in
 * nanoseconds to avoid any conversion.
 */
struct lf_keymanager_key_container {
	uint64_t validity_not_before; /* Unix timestamp (nanoseconds) */
	uint64_t validity_not_after;  /* Unix timestamp (nanoseconds) */
	struct lf_crypto_drkey key;
};

struct lf_keymanager_worker {
	struct rte_hash *dict;
	struct lf_crypto_drkey_ctx drkey_ctx;
};

struct lf_keymanager_dictionary_data {
	/* newest keys */
	struct lf_keymanager_key_container outbound_key;
	struct lf_keymanager_key_container inbound_key;
	/* previous keys */
	struct lf_keymanager_key_container old_inbound_key;
	struct lf_keymanager_key_container old_outbound_key;
};

struct lf_keymanager_dictionary_key {
	uint64_t as;             /* network byte order */
	uint16_t drkey_protocol; /* network byte order */
} __attribute__((__packed__));


#define LF_KEYMANAGER_STATISTICS(M) \
	M(uint64_t, fetch_successful)   \
	M(uint64_t, fetch_fail)

struct lf_keymanager_statistics {
	LF_KEYMANAGER_STATISTICS(LF_TELEMETRY_FIELD_DECL)
};

struct lf_keymanager {
	struct lf_keymanager_worker workers[LF_MAX_WORKER];
	uint16_t nb_workers;

	/* AS-AS DRKey dictionary */
	struct rte_hash *dict;
	/* max number of entries */
	uint32_t size;

	uint64_t src_as;

	char drkey_service_addr[48];

	/* crypto DRKey context */
	struct lf_crypto_drkey_ctx drkey_ctx;

	/* synchronize management */
	rte_spinlock_t management_lock;
	/* Workers' Quiescent State Variable */
	struct rte_rcu_qsbr *qsv;

	/* statistics counters */
	struct lf_keymanager_statistics statistics;
};

/**
 * Check if DRKey is valid at the requested time.
 *
 * @param drkey: DRKey to be checked.
 * @param ns_valid: Unix timestamp in nanoseconds, at which the requested key
 * must be valid.
 * @return Returns 0 if the requested time is within the DRKey's epoch. Returns
 * 1 if the DRKey is valid only due to the grace period.
 */
static inline int
lf_keymanager_check_drkey_validity(struct lf_keymanager_key_container *drkey,
		uint64_t ns_valid)
{
	if (likely(ns_valid >= drkey->validity_not_before &&
				ns_valid < drkey->validity_not_after)) {
		return 0;
	}

	if (likely(ns_valid >= drkey->validity_not_before &&
				ns_valid < drkey->validity_not_after + LF_DRKEY_GRACE_PERIOD)) {
		return 1;
	}

	return -1;
}

/**
 * Derive host-host DRKey from AS-AS DRKey.
 *
 * @param kmw Keymanager worker context.
 * @param drkey_asas AS-AS DRKey.
 * @param fast_side_host Fast side host address.
 * @param slow_side_host Slow side host address.
 * @param drkey_hh Returning host-host DRKey.
 */
static inline void
lf_keymanager_drkey_from_asas(struct lf_keymanager_worker *kmw,
		const struct lf_crypto_drkey *drkey_asas,
		const struct lf_host_addr *fast_side_host,
		const struct lf_host_addr *slow_side_host,
		struct lf_crypto_drkey *drkey_hh)
{
	assert(LF_HOST_ADDR_LENGTH(fast_side_host) <= LF_CRYPTO_CBC_BLOCK_SIZE);
	assert(LF_HOST_ADDR_LENGTH(slow_side_host) <= LF_CRYPTO_CBC_BLOCK_SIZE);

	/* TODO: prepend key type and address length/type */
	uint8_t buf[2 * LF_CRYPTO_CBC_BLOCK_SIZE] = { 0 };

	memcpy(buf, fast_side_host->addr, LF_HOST_ADDR_LENGTH(fast_side_host));
	memcpy(buf + LF_CRYPTO_CBC_BLOCK_SIZE, slow_side_host->addr,
			LF_HOST_ADDR_LENGTH(slow_side_host));

	lf_crypto_drkey_derivation_step(&kmw->drkey_ctx, drkey_asas, buf,
			sizeof(buf), drkey_hh);
}

/**
 * Obtain inbound DRKey.
 *
 * @param peer_as: Packet's source AS (network byte order).
 * @param peer_addr: Packet's source address (network byte order).
 * @param backend_addr: Packet's destination address (network byte
 * order).
 * @param drkey_protocol: (network byte order).
 * @param ns_valid: Unix timestamp in nanoseconds, at which the requested key
 * must be valid.
 * @param grace_period: Indicator that the DRKey is in the grace period.
 * @param drkey: Memory to write DRKey to.
 * @return 0 if success. Otherwise, < 0.
 */
static inline int
lf_keymanager_worker_inbound_get_drkey(struct lf_keymanager_worker *kmw,
		uint64_t peer_as, const struct lf_host_addr *peer_addr,
		const struct lf_host_addr *backend_addr, uint16_t drkey_protocol,
		uint64_t ns_valid, bool grace_period, struct lf_crypto_drkey *drkey)
{
	int res;
	int key_id;
	struct lf_keymanager_dictionary_data *dict_node;
	struct lf_keymanager_dictionary_key key = {
		.as = peer_as,
		.drkey_protocol = drkey_protocol,
	};

	/* find AS-AS key */
	key_id = rte_hash_lookup_data(kmw->dict, &key, (void **)&dict_node);
	if (unlikely(key_id < 0)) {
		return -1;
	}

	/* Check if the new key is valid and and is in the grace period if
	 * requested. */
	res = lf_keymanager_check_drkey_validity(&dict_node->inbound_key, ns_valid);
#if LF_WORKER_IGNORE_KEY_VALIDITY_CHECK
	res = 0;
	grace_period = 0;
#endif
	if (res >= 0 && (res == grace_period)) {
		lf_keymanager_drkey_from_asas(kmw, &dict_node->inbound_key.key,
				backend_addr, peer_addr, drkey);
		return 0;
	}

	/* Check if the new key is valid and and is in the grace period if
	 * requested. */
	res = lf_keymanager_check_drkey_validity(&dict_node->old_inbound_key,
			ns_valid);
	if (res >= 0 && (res == grace_period)) {
		lf_keymanager_drkey_from_asas(kmw, &dict_node->old_inbound_key.key,
				backend_addr, peer_addr, drkey);
		return 0;
	}

	return -2;
}

/**
 * Obtain an outbound DRKey that is valid (including grace period) at the
 * requested time. If two valid DRKeys are available, which is possible due to
 * the grace period, the newer key is returned which is not in the grace period.
 *
 * @param peer_as: Packet's destination AS (network byte order).
 * @param peer_addr: Packet's destination address (network byte order).
 * @param backend_addr: Packet's source address (network byte order).
 * @param drkey_protocol: (network byte order).
 * @param ns_valid: Unix timestamp in nanoseconds, at which the requested key
 * must be valid.
 * @param drkey: Memory to write DRKey to.
 * @return Returns 0 if a DRKey has been found which is valid for the requested
 * time. Returns 1 if a DRKey has been found that is in the grace period.
 * Otherwise, a negative number is returned
 */
static inline int
lf_keymanager_worker_outbound_get_drkey(struct lf_keymanager_worker *kmw,
		uint64_t peer_as, const struct lf_host_addr *peer_addr,
		const struct lf_host_addr *backend_addr, uint16_t drkey_protocol,
		uint64_t ns_valid, struct lf_crypto_drkey *drkey)
{
	int res;
	int key_id;
	struct lf_keymanager_dictionary_data *dict_node;
	struct lf_keymanager_dictionary_key key = {
		.as = peer_as,
		.drkey_protocol = drkey_protocol,
	};

	/* find AS-AS key */
	key_id = rte_hash_lookup_data(kmw->dict, &key, (void **)&dict_node);
	if (unlikely(key_id < 0)) {
		return -1;
	}

	/* Check first if the new key is valid */
	res = lf_keymanager_check_drkey_validity(&dict_node->outbound_key,
			ns_valid);
#if LF_WORKER_IGNORE_KEY_VALIDITY_CHECK
	res = 0;
#endif
	if (likely(res == 0 || res == 1)) {
		lf_keymanager_drkey_from_asas(kmw, &dict_node->outbound_key.key,
				peer_addr, backend_addr, drkey);
		return res;
	}

	/* Check if the old key is valid */
	res = lf_keymanager_check_drkey_validity(&dict_node->old_outbound_key,
			ns_valid);
	if (likely(res == 0 || res == 1)) {
		lf_keymanager_drkey_from_asas(kmw, &dict_node->old_outbound_key.key,
				peer_addr, backend_addr, drkey);
		return res;
	}

	return -2;
}

/**
 * Launch function for keymanager service.
 */
int
lf_keymanager_service_launch(struct lf_keymanager *km);

/**
 * Replaces current config with new config.
 * @param config: new config
 * @return 0 on success, otherwise, -1.
 */
int
lf_keymanager_apply_config(struct lf_keymanager *km,
		const struct lf_config *config);

/**
 * Frees the content of the keymanager struct (not itself).
 * This includes also the workers' structs. Hence, all the workers have to
 * terminate beforehand.
 */
int
lf_keymanager_close(struct lf_keymanager *km);

/**
 * @param qsv workers' QS variable for the RCU synchronization. The QS variable
 * can be shared with other services, i.e., other processes call check on it,
 * because the keymanager service calls it rarely and can also wait.
 */
int
lf_keymanager_init(struct lf_keymanager *km, uint16_t nb_workers,
		uint32_t initial_size, struct rte_rcu_qsbr *qsv);


/**
 * Register keymanager IPC commands for the provided context.
 */
int
lf_keymanager_register_ipc(struct lf_keymanager *km);


/**
 * Register keymanager telemetry commands for the provided context.
 */
int
lf_keymanager_register_telemetry(struct lf_keymanager *km);

#endif /* LF_KEYMANAGER_H */