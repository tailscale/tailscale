/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */
#ifndef _WG_NOISE_H
#define _WG_NOISE_H

#include "messages.h"
#include "peerlookup.h"

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/rwsem.h>
#include <linux/mutex.h>
#include <linux/kref.h>

struct noise_replay_counter {
	u64 counter;
	spinlock_t lock;
	unsigned long backtrack[COUNTER_BITS_TOTAL / BITS_PER_LONG];
};

struct noise_symmetric_key {
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u64 birthdate;
	bool is_valid;
};

struct noise_keypair {
	struct index_hashtable_entry entry;
	struct noise_symmetric_key sending;
	atomic64_t sending_counter;
	struct noise_symmetric_key receiving;
	struct noise_replay_counter receiving_counter;
	__le32 remote_index;
	bool i_am_the_initiator;
	struct kref refcount;
	struct rcu_head rcu;
	u64 internal_id;
};

struct noise_keypairs {
	struct noise_keypair __rcu *current_keypair;
	struct noise_keypair __rcu *previous_keypair;
	struct noise_keypair __rcu *next_keypair;
	spinlock_t keypair_update_lock;
};

struct noise_static_identity {
	u8 static_public[NOISE_PUBLIC_KEY_LEN];
	u8 static_private[NOISE_PUBLIC_KEY_LEN];
	struct rw_semaphore lock;
	bool has_identity;
};

enum noise_handshake_state {
	HANDSHAKE_ZEROED,
	HANDSHAKE_CREATED_INITIATION,
	HANDSHAKE_CONSUMED_INITIATION,
	HANDSHAKE_CREATED_RESPONSE,
	HANDSHAKE_CONSUMED_RESPONSE
};

struct noise_handshake {
	struct index_hashtable_entry entry;

	enum noise_handshake_state state;
	u64 last_initiation_consumption;

	struct noise_static_identity *static_identity;

	u8 ephemeral_private[NOISE_PUBLIC_KEY_LEN];
	u8 remote_static[NOISE_PUBLIC_KEY_LEN];
	u8 remote_ephemeral[NOISE_PUBLIC_KEY_LEN];
	u8 precomputed_static_static[NOISE_PUBLIC_KEY_LEN];

	u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN];

	u8 hash[NOISE_HASH_LEN];
	u8 chaining_key[NOISE_HASH_LEN];

	u8 latest_timestamp[NOISE_TIMESTAMP_LEN];
	__le32 remote_index;

	/* TSWG: whether to do hybrid handshakes with this peer; see noise.c. */
	bool hybrid;
	/*
	 * TSWG: in a hybrid handshake, our ML-KEM decapsulation key while
	 * we're the initiator (HANDSHAKE_CREATED_INITIATION), or the peer's
	 * encapsulation key while we're the responder
	 * (HANDSHAKE_CONSUMED_INITIATION); otherwise NULL. Allocated with
	 * TSWG_MLKEM768_DK_LEN bytes.
	 */
	u8 *kem;

	/* Protects all members except the immutable (after noise_handshake_
	 * init): remote_static, precomputed_static_static, static_identity.
 * TSWG: but tswg_peer_rename changes remote_static (and so
 * precomputed_static_static), under this lock and the device's
 * device_update_lock, having first cleared the handshake and keypairs.
	 */
	struct rw_semaphore lock;
};

struct wg_device;

void wg_noise_init(void);
void wg_noise_handshake_init(struct noise_handshake *handshake,
			     struct noise_static_identity *static_identity,
			     const u8 peer_public_key[NOISE_PUBLIC_KEY_LEN],
			     const u8 peer_preshared_key[NOISE_SYMMETRIC_KEY_LEN],
			     struct wg_peer *peer);
void wg_noise_handshake_clear(struct noise_handshake *handshake);
static inline void wg_noise_reset_last_sent_handshake(atomic64_t *handshake_ns)
{
	atomic64_set(handshake_ns, ktime_get_coarse_boottime_ns() -
				       (u64)(REKEY_TIMEOUT + 1) * NSEC_PER_SEC);
}

void wg_noise_keypair_put(struct noise_keypair *keypair, bool unreference_now);
struct noise_keypair *wg_noise_keypair_get(struct noise_keypair *keypair);
void wg_noise_keypairs_clear(struct noise_keypairs *keypairs);
bool wg_noise_received_with_keypair(struct noise_keypairs *keypairs,
				    struct noise_keypair *received_keypair);
void wg_noise_expire_current_peer_keypairs(struct wg_peer *peer);

void wg_noise_set_static_identity_private_key(
	struct noise_static_identity *static_identity,
	const u8 private_key[NOISE_PUBLIC_KEY_LEN]);
void wg_noise_precompute_static_static(struct wg_peer *peer);

/*
 * TSWG: the handshake functions take the classic messages, and for hybrid
 * handshakes, separately, the encrypted_kem field of the hybrid message
 * (NULL when consuming a classic one). The create functions decide which
 * kind of handshake it is, reporting it in *hybrid; send.c and receive.c
 * convert between the classic messages and the hybrid ones.
 */
bool
wg_noise_handshake_create_initiation(struct message_handshake_initiation *dst,
				     u8 *dst_kem, bool *hybrid,
				     struct noise_handshake *handshake);
struct wg_peer *
wg_noise_handshake_consume_initiation(struct message_handshake_initiation *src,
				      const u8 *src_kem, struct wg_device *wg);

bool wg_noise_handshake_create_response(struct message_handshake_response *dst,
					u8 *dst_kem, bool *hybrid,
					struct noise_handshake *handshake);
struct wg_peer *
wg_noise_handshake_consume_response(struct message_handshake_response *src,
				    const u8 *src_kem, struct wg_device *wg);
void tswg_noise_set_hybrid(struct noise_handshake *handshake, bool hybrid);

bool wg_noise_handshake_begin_session(struct noise_handshake *handshake,
				      struct noise_keypairs *keypairs);

#endif /* _WG_NOISE_H */
