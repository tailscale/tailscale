/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TSWG: ChaCha20-Poly1305 for data messages, as lib/crypto's
 * chacha20poly1305_encrypt and chacha20poly1305_decrypt (RFC 8439, with no
 * additional data), but faster for packet-sized messages.
 *
 * The library makes the Poly1305 key from 32 bytes of ChaCha20 keystream
 * (block 0), and x86's ChaCha20 does anything up to a block with its
 * portable code: one scalar ChaCha20 block per message, which was 5.5% of a
 * CPU-bound subnet router's CPU. We ask for two blocks instead, which takes
 * the SIMD path, and set the block counter back to 1 for the message; or,
 * better, when decrypting from one buffer to another, get block 0 in the
 * same pass as the message (see tswg_aead_decrypt_ahead).
 */

#ifndef _TSWG_AEAD_H
#define _TSWG_AEAD_H

#include <crypto/chacha.h>
#include <crypto/poly1305.h>
#include <crypto/utils.h>
#if __has_include(<linux/unaligned.h>)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h> /* before 6.12 */
#endif

#ifndef CHACHA_KEY_WORDS
#define CHACHA_KEY_WORDS (CHACHA_KEY_SIZE / sizeof(u32)) /* before 6.10 */
#endif

/* tswg_chacha is ChaCha's state, as the library wants it. */
struct tswg_chacha {
	u32 x[CHACHA_STATE_WORDS];
};

#ifdef HAVE_STRUCT_CHACHA_STATE
#define TSWG_CHACHA(s) ((struct chacha_state *)(s))
#else
#define TSWG_CHACHA(s) ((s)->x)
#endif

/* tswg_aead_init initializes state for a message with nonce and key. */
static inline void tswg_aead_init(struct tswg_chacha *state, u64 nonce,
				  const u8 key[CHACHA20POLY1305_KEY_SIZE])
{
	u32 k[CHACHA_KEY_WORDS];
	__le64 iv[2];
	int i;

	BUILD_BUG_ON(sizeof(struct tswg_chacha) != CHACHA_STATE_WORDS * sizeof(u32));
	for (i = 0; i < CHACHA_KEY_WORDS; i++)
		k[i] = get_unaligned_le32(key + i * sizeof(u32));
	iv[0] = 0;
	iv[1] = cpu_to_le64(nonce);
	chacha_init(TSWG_CHACHA(state), k, (u8 *)iv);
	memzero_explicit(k, sizeof(k));
}

/*
 * tswg_aead_begin initializes state for a message with nonce and key, and
 * makes the message's Poly1305 key into poly.
 */
static inline void tswg_aead_begin(struct tswg_chacha *state,
				   struct poly1305_desc_ctx *poly, u64 nonce,
				   const u8 key[CHACHA20POLY1305_KEY_SIZE])
{
	static const u8 zeros[2 * CHACHA_BLOCK_SIZE];
	u8 block0[2 * CHACHA_BLOCK_SIZE];

	tswg_aead_init(state, nonce, key);
	chacha20_crypt(TSWG_CHACHA(state), block0, zeros, sizeof(block0));
	state->x[12] = 1; /* the message starts at block 1 */
	poly1305_init(poly, block0);
	memzero_explicit(block0, sizeof(block0));
}

/* tswg_aead_mac finishes poly over a message of len bytes into mac. */
static inline void tswg_aead_mac(struct poly1305_desc_ctx *poly, size_t len,
				 u8 mac[POLY1305_DIGEST_SIZE])
{
	static const u8 pad0[16];
	__le64 lens[2];

	if (len & 0xf)
		poly1305_update(poly, pad0, 0x10 - (len & 0xf));
	lens[0] = 0;
	lens[1] = cpu_to_le64(len);
	poly1305_update(poly, (u8 *)lens, sizeof(lens));
	poly1305_final(poly, mac);
}

/*
 * tswg_aead_encrypt encrypts len bytes from src to dst (which may be the
 * same), followed by the tag.
 */
static inline void tswg_aead_encrypt(u8 *dst, const u8 *src, size_t len,
				     u64 nonce,
				     const u8 key[CHACHA20POLY1305_KEY_SIZE])
{
	struct poly1305_desc_ctx poly;
	struct tswg_chacha state;

	tswg_aead_begin(&state, &poly, nonce, key);
	chacha20_crypt(TSWG_CHACHA(&state), dst, src, len);
	poly1305_update(&poly, dst, len);
	tswg_aead_mac(&poly, len, dst + len);
	memzero_explicit(&state, sizeof(state));
}

/*
 * tswg_aead_decrypt authenticates and decrypts src_len bytes (the
 * ciphertext and its tag) from src to dst (which may be the same), and
 * reports whether they authenticated. dst gets src_len minus the tag's
 * length bytes, only if they did.
 */
static inline bool tswg_aead_decrypt(u8 *dst, const u8 *src, size_t src_len,
				     u64 nonce,
				     const u8 key[CHACHA20POLY1305_KEY_SIZE])
{
	size_t len = src_len - POLY1305_DIGEST_SIZE;
	struct poly1305_desc_ctx poly;
	u8 mac[POLY1305_DIGEST_SIZE];
	struct tswg_chacha state;
	bool ok;

	if (unlikely(src_len < POLY1305_DIGEST_SIZE))
		return false;
	tswg_aead_begin(&state, &poly, nonce, key);
	poly1305_update(&poly, src, len);
	tswg_aead_mac(&poly, len, mac);
	ok = !crypto_memneq(mac, src + len, POLY1305_DIGEST_SIZE);
	if (likely(ok))
		chacha20_crypt(TSWG_CHACHA(&state), dst, src, len);
	memzero_explicit(&state, sizeof(state));
	memzero_explicit(mac, sizeof(mac));
	return ok;
}

/*
 * tswg_aead_decrypt_ahead is tswg_aead_decrypt from one buffer to another,
 * when the CHACHA_BLOCK_SIZE bytes before src are readable and those before
 * dst are writable (and disposable; it zeroes them). It runs ChaCha20 over
 * them too, from block 0, and so gets the Poly1305 key, block 0's
 * keystream, as what's before dst XOR what's before src, in the same pass
 * as the message. dst may get unauthenticated plaintext; drop it on failure.
 */
static inline bool tswg_aead_decrypt_ahead(u8 *dst, const u8 *src,
					   size_t src_len, u64 nonce,
					   const u8 key[CHACHA20POLY1305_KEY_SIZE])
{
	size_t len = src_len - POLY1305_DIGEST_SIZE;
	u8 mac[POLY1305_DIGEST_SIZE], polykey[POLY1305_KEY_SIZE];
	struct poly1305_desc_ctx poly;
	struct tswg_chacha state;
	bool ok;
	int i;

	if (unlikely(src_len < POLY1305_DIGEST_SIZE))
		return false;
	tswg_aead_init(&state, nonce, key);
	chacha20_crypt(TSWG_CHACHA(&state), dst - CHACHA_BLOCK_SIZE,
		       src - CHACHA_BLOCK_SIZE, CHACHA_BLOCK_SIZE + len);
	for (i = 0; i < POLY1305_KEY_SIZE; i++)
		polykey[i] = dst[i - CHACHA_BLOCK_SIZE] ^ src[i - CHACHA_BLOCK_SIZE];
	memzero_explicit(dst - CHACHA_BLOCK_SIZE, CHACHA_BLOCK_SIZE);
	poly1305_init(&poly, polykey);
	poly1305_update(&poly, src, len);
	tswg_aead_mac(&poly, len, mac);
	ok = !crypto_memneq(mac, src + len, POLY1305_DIGEST_SIZE);
	memzero_explicit(&state, sizeof(state));
	memzero_explicit(polykey, sizeof(polykey));
	memzero_explicit(mac, sizeof(mac));
	return ok;
}

#endif /* _TSWG_AEAD_H */
