/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _WG_PEERLOOKUP_H
#define _WG_PEERLOOKUP_H

#include "messages.h"

#include <linux/hashtable.h>
#include <linux/mutex.h>
#include <linux/siphash.h>

struct wg_peer;

struct pubkey_hashtable {
	/*
	 * TSWG: 2^16 buckets (512KB), for a 50,000-node tailnet, rather than
	 * upstream's 2^11, at which lookups walked chains of 25.
	 */
	DECLARE_HASHTABLE(hashtable, 16);
	siphash_key_t key;
	struct mutex lock;
};

struct pubkey_hashtable *wg_pubkey_hashtable_alloc(void);
void wg_pubkey_hashtable_add(struct pubkey_hashtable *table,
			     struct wg_peer *peer);
void wg_pubkey_hashtable_remove(struct pubkey_hashtable *table,
				struct wg_peer *peer);
struct wg_peer *
wg_pubkey_hashtable_lookup(struct pubkey_hashtable *table,
			   const u8 pubkey[NOISE_PUBLIC_KEY_LEN]);

struct index_hashtable {
	/*
	 * TSWG: 2^17 buckets (1MB), for a handshake and up to three keypairs
	 * each of 50,000 peers, rather than upstream's 2^13.
	 */
	DECLARE_HASHTABLE(hashtable, 17);
	spinlock_t lock;
};

enum index_hashtable_type {
	INDEX_HASHTABLE_HANDSHAKE = 1U << 0,
	INDEX_HASHTABLE_KEYPAIR = 1U << 1
};

struct index_hashtable_entry {
	struct wg_peer *peer;
	struct hlist_node index_hash;
	enum index_hashtable_type type;
	__le32 index;
};

struct index_hashtable *wg_index_hashtable_alloc(void);
__le32 wg_index_hashtable_insert(struct index_hashtable *table,
				 struct index_hashtable_entry *entry);
bool wg_index_hashtable_replace(struct index_hashtable *table,
				struct index_hashtable_entry *old,
				struct index_hashtable_entry *new);
void wg_index_hashtable_remove(struct index_hashtable *table,
			       struct index_hashtable_entry *entry);
struct index_hashtable_entry *
wg_index_hashtable_lookup(struct index_hashtable *table,
			  const enum index_hashtable_type type_mask,
			  const __le32 index, struct wg_peer **peer);

#endif /* _WG_PEERLOOKUP_H */
