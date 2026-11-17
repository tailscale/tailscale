// SPDX-License-Identifier: GPL-2.0
/*
 * TSWG: ML-KEM-768 (FIPS 203), for the hybrid post-quantum handshake of
 * Tailscale's wireguard-go (Noise_IKhfs+psk2_25519+MLKEM768). Linux has
 * no ML-KEM, and its SHA-3 is too new for the kernels we build for, so
 * this has its own Keccak. It's written for clarity over speed: it runs
 * a few times per handshake, in process context. Arithmetic is on
 * coefficients reduced to [0, q) with "% q", which compilers turn into
 * multiplications (no data-dependent division); nothing else branches on
 * secrets, and decapsulation's implicit rejection is a constant-time
 * select.
 *
 * Checked against Go's crypto/mlkem by tests/mlkem.
 */

#include "mlkem.h"

#include <linux/bitops.h>
#include <linux/cache.h>
#include <linux/errno.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <crypto/utils.h>

enum {
	MLKEM_N = 256,
	MLKEM_Q = 3329,
	MLKEM_K = 3,
	MLKEM_DU = 10,
	MLKEM_DV = 4,
	MLKEM_POLY_BYTES = 384, /* ByteEncode12 of a polynomial */
	MLKEM_PKE_DK_LEN = MLKEM_K * MLKEM_POLY_BYTES,
	MLKEM_U_BYTES = 32 * MLKEM_DU, /* ByteEncode10 of a polynomial */
	MLKEM_PRF_LEN = 64 * 2 /* eta = 2, for both eta1 and eta2 */
};

/* Keccak-f[1600] and the SHA-3 sponge (FIPS 202). */

static const u64 keccak_rc[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
	0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
	0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
	0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const u8 keccak_rho[24] = {
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
	27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const u8 keccak_pi[24] = {
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static void keccakf(u64 st[25])
{
	u64 bc[5], t;
	int i, j, r;

	for (r = 0; r < 24; r++) {
		/* θ */
		for (i = 0; i < 5; i++)
			bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
		for (i = 0; i < 5; i++) {
			t = bc[(i + 4) % 5] ^ rol64(bc[(i + 1) % 5], 1);
			for (j = 0; j < 25; j += 5)
				st[j + i] ^= t;
		}
		/* ρ and π */
		t = st[1];
		for (i = 0; i < 24; i++) {
			j = keccak_pi[i];
			bc[0] = st[j];
			st[j] = rol64(t, keccak_rho[i]);
			t = bc[0];
		}
		/* χ */
		for (j = 0; j < 25; j += 5) {
			for (i = 0; i < 5; i++)
				bc[i] = st[j + i];
			for (i = 0; i < 5; i++)
				st[j + i] ^= ~bc[(i + 1) % 5] & bc[(i + 2) % 5];
		}
		/* ι */
		st[0] ^= keccak_rc[r];
	}
}

struct keccak {
	u64 st[25];
	unsigned int rate; /* in bytes */
	unsigned int pos; /* next byte of the rate to absorb or squeeze */
};

enum {
	SHA3_256_RATE = 136,
	SHA3_512_RATE = 72,
	SHAKE128_RATE = 168,
	SHAKE256_RATE = 136,
	SHA3_DS = 0x06, /* domain separation and first padding bit */
	SHAKE_DS = 0x1f
};

static void keccak_init(struct keccak *k, unsigned int rate)
{
	memset(k->st, 0, sizeof(k->st));
	k->rate = rate;
	k->pos = 0;
}

static void keccak_xor_byte(struct keccak *k, unsigned int i, u8 b)
{
	k->st[i / 8] ^= (u64)b << (8 * (i % 8));
}

static void keccak_absorb(struct keccak *k, const u8 *in, size_t len)
{
	while (len--) {
		keccak_xor_byte(k, k->pos++, *in++);
		if (k->pos == k->rate) {
			keccakf(k->st);
			k->pos = 0;
		}
	}
}

/* keccak_finish pads the input, after which k may only be squeezed. */
static void keccak_finish(struct keccak *k, u8 ds)
{
	keccak_xor_byte(k, k->pos, ds);
	keccak_xor_byte(k, k->rate - 1, 0x80);
	keccakf(k->st);
	k->pos = 0;
}

static void keccak_squeeze(struct keccak *k, u8 *out, size_t len)
{
	while (len--) {
		if (k->pos == k->rate) {
			keccakf(k->st);
			k->pos = 0;
		}
		*out++ = k->st[k->pos / 8] >> (8 * (k->pos % 8));
		k->pos++;
	}
}

/*
 * keccak2 hashes the concatenation of a and b (b may be empty) into out,
 * with the given rate and domain separation byte.
 */
static void keccak2(struct keccak *k, unsigned int rate, u8 ds,
		    const u8 *a, size_t a_len, const u8 *b, size_t b_len,
		    u8 *out, size_t out_len)
{
	keccak_init(k, rate);
	keccak_absorb(k, a, a_len);
	keccak_absorb(k, b, b_len);
	keccak_finish(k, ds);
	keccak_squeeze(k, out, out_len);
}

/* Polynomials, the NTT and the encodings (FIPS 203, section 4). */

typedef u16 poly[MLKEM_N]; /* coefficients in [0, q) */

/*
 * mlkem_zetas[i] is 17^BitRev7(i) mod q, and mlkem_gammas[i] is
 * 17^(2 BitRev7(i) + 1) mod q (FIPS 203, appendix A), computed at init
 * rather than transcribed.
 */
static u16 mlkem_zetas[128] __ro_after_init;
static u16 mlkem_gammas[128] __ro_after_init;

static u32 mlkem_pow17(unsigned int e)
{
	u32 r = 1;

	while (e--)
		r = r * 17 % MLKEM_Q;
	return r;
}

/* BitRev7 (not bitrev8, which needs CONFIG_BITREVERSE). */
static unsigned int mlkem_bitrev7(unsigned int x)
{
	unsigned int i, r = 0;

	for (i = 0; i < 7; i++)
		r |= (x >> i & 1) << (6 - i);
	return r;
}

void tswg_mlkem_init(void)
{
	unsigned int i, rev;

	for (i = 0; i < 128; i++) {
		rev = mlkem_bitrev7(i);
		mlkem_zetas[i] = mlkem_pow17(rev);
		mlkem_gammas[i] = mlkem_pow17(2 * rev + 1);
	}
}

static u16 mod_q(u32 x)
{
	return x % MLKEM_Q;
}

/* Algorithm 9, NTT. */
static void poly_ntt(poly f)
{
	unsigned int len, start, j, i = 1;
	u16 zeta, t;

	for (len = 128; len >= 2; len /= 2) {
		for (start = 0; start < MLKEM_N; start += 2 * len) {
			zeta = mlkem_zetas[i++];
			for (j = start; j < start + len; j++) {
				t = mod_q((u32)zeta * f[j + len]);
				f[j + len] = mod_q(f[j] + MLKEM_Q - t);
				f[j] = mod_q(f[j] + t);
			}
		}
	}
}

/* Algorithm 10, NTT^-1. */
static void poly_invntt(poly f)
{
	unsigned int len, start, j, i = 127;
	u16 zeta, t;

	for (len = 2; len <= 128; len *= 2) {
		for (start = 0; start < MLKEM_N; start += 2 * len) {
			zeta = mlkem_zetas[i--];
			for (j = start; j < start + len; j++) {
				t = f[j];
				f[j] = mod_q(t + f[j + len]);
				f[j + len] = mod_q((u32)zeta * (f[j + len] + MLKEM_Q - t));
			}
		}
	}
	for (j = 0; j < MLKEM_N; j++)
		f[j] = mod_q((u32)f[j] * 3303); /* 3303 = 128^-1 mod q */
}

/* poly_mul_acc adds a * b (Algorithm 11, MultiplyNTTs) to acc. */
static void poly_mul_acc(poly acc, const poly a, const poly b)
{
	unsigned int i;
	u32 c0, c1;

	for (i = 0; i < 128; i++) {
		/* Algorithm 12, BaseCaseMultiply. */
		c0 = (u32)a[2 * i] * b[2 * i] +
		     (u32)mod_q((u32)a[2 * i + 1] * b[2 * i + 1]) * mlkem_gammas[i];
		c1 = (u32)a[2 * i] * b[2 * i + 1] + (u32)a[2 * i + 1] * b[2 * i];
		acc[2 * i] = mod_q(acc[2 * i] + c0);
		acc[2 * i + 1] = mod_q(acc[2 * i + 1] + c1);
	}
}

static void poly_add(poly f, const poly g)
{
	unsigned int i;

	for (i = 0; i < MLKEM_N; i++)
		f[i] = mod_q(f[i] + g[i]);
}

/* Algorithm 5, ByteEncode_d, for d <= 12. */
static void poly_encode(u8 *out, const poly f, unsigned int d)
{
	unsigned int i, bits = 0;
	u32 acc = 0;

	for (i = 0; i < MLKEM_N; i++) {
		acc |= (u32)f[i] << bits;
		bits += d;
		while (bits >= 8) {
			*out++ = acc;
			acc >>= 8;
			bits -= 8;
		}
	}
}

/* Algorithm 6, ByteDecode_d, for d <= 12, without reducing mod q. */
static void poly_decode(poly f, const u8 *in, unsigned int d)
{
	unsigned int i, bits = 0;
	u32 acc = 0;

	for (i = 0; i < MLKEM_N; i++) {
		while (bits < d) {
			acc |= (u32)*in++ << bits;
			bits += 8;
		}
		f[i] = acc & ((1U << d) - 1);
		acc >>= d;
		bits -= d;
	}
}

/* poly_decode12 is ByteDecode12, which reduces mod q. */
static void poly_decode12(poly f, const u8 *in)
{
	unsigned int i;

	poly_decode(f, in, 12);
	for (i = 0; i < MLKEM_N; i++)
		f[i] = mod_q(f[i]);
}

/* Compress_d and Decompress_d (section 4.2.1), in place. */
static void poly_compress(poly f, unsigned int d)
{
	unsigned int i;

	for (i = 0; i < MLKEM_N; i++)
		f[i] = (((u32)f[i] << d) + MLKEM_Q / 2) / MLKEM_Q & ((1U << d) - 1);
}

static void poly_decompress(poly f, unsigned int d)
{
	unsigned int i;

	for (i = 0; i < MLKEM_N; i++)
		f[i] = ((u32)f[i] * MLKEM_Q + (1U << (d - 1))) >> d;
}

/* Algorithm 8, SamplePolyCBD_2, of PRF_2(seed, n) (SHAKE256). */
static void poly_cbd2(struct keccak *k, poly f, const u8 seed[32], u8 n)
{
	u8 buf[MLKEM_PRF_LEN];
	unsigned int i, h;
	u8 b;

	keccak2(k, SHAKE256_RATE, SHAKE_DS, seed, 32, &n, 1, buf, sizeof(buf));
	for (i = 0; i < MLKEM_N / 2; i++) {
		b = buf[i];
		for (h = 0; h < 2; h++, b >>= 4)
			f[2 * i + h] = mod_q(MLKEM_Q + (b & 1) + (b >> 1 & 1) -
					     (b >> 2 & 1) - (b >> 3 & 1));
	}
	memzero_explicit(buf, sizeof(buf));
}

/*
 * Algorithm 7, SampleNTT, of rho || x || y: Â[y][x] (FIPS 203 samples
 * Â[i, j] from rho || j || i).
 */
static void poly_sample_ntt(struct keccak *k, poly f, const u8 rho[32],
			    u8 x, u8 y)
{
	u8 buf[SHAKE128_RATE];
	unsigned int i, j = 0;
	u16 d1, d2;

	keccak_init(k, SHAKE128_RATE);
	keccak_absorb(k, rho, 32);
	keccak_absorb(k, &x, 1);
	keccak_absorb(k, &y, 1);
	keccak_finish(k, SHAKE_DS);
	while (j < MLKEM_N) {
		keccak_squeeze(k, buf, sizeof(buf));
		for (i = 0; i < sizeof(buf) && j < MLKEM_N; i += 3) {
			d1 = buf[i] | (buf[i + 1] & 0xf) << 8;
			d2 = buf[i + 1] >> 4 | buf[i + 2] << 4;
			if (d1 < MLKEM_Q)
				f[j++] = d1;
			if (d2 < MLKEM_Q && j < MLKEM_N)
				f[j++] = d2;
		}
	}
}

/* K-PKE and ML-KEM (sections 5 and 6), with a heap workspace. */

struct mlkem_ws {
	struct keccak k;
	poly a; /* a sampled matrix entry */
	poly acc;
	poly v[MLKEM_K]; /* ŝ; or t̂ */
	poly w[MLKEM_K]; /* ê then t̂; or ŷ; or û */
	poly e; /* e1[i], e2 */
	u8 g[64]; /* G's output */
	u8 m[32];
	u8 ct[TSWG_MLKEM768_CT_LEN]; /* re-encryption, for decapsulation */
};

static struct mlkem_ws *mlkem_ws_alloc(void)
{
	return kmalloc(sizeof(struct mlkem_ws), GFP_KERNEL);
}

static void mlkem_ws_free(struct mlkem_ws *ws)
{
	kfree_sensitive(ws);
}

/* G is SHA3-512, H is SHA3-256, and J is SHAKE256 with 32 bytes out. */
static void mlkem_g(struct mlkem_ws *ws, const u8 *a, size_t a_len,
		    const u8 *b, size_t b_len)
{
	keccak2(&ws->k, SHA3_512_RATE, SHA3_DS, a, a_len, b, b_len, ws->g, 64);
}

static void mlkem_h(struct mlkem_ws *ws, u8 out[32], const u8 *in, size_t len)
{
	keccak2(&ws->k, SHA3_256_RATE, SHA3_DS, in, len, NULL, 0, out, 32);
}

/*
 * Algorithm 13, K-PKE.KeyGen, from d, writing ek (the K-PKE and ML-KEM
 * encapsulation keys are the same) and the K-PKE decapsulation key.
 */
static void kpke_keygen(struct mlkem_ws *ws, u8 *ek, u8 *pke_dk, const u8 d[32])
{
	const u8 k = MLKEM_K;
	const u8 *rho = ws->g, *sigma = ws->g + 32;
	unsigned int i, j;

	mlkem_g(ws, d, 32, &k, 1);
	for (i = 0; i < MLKEM_K; i++) {
		poly_cbd2(&ws->k, ws->v[i], sigma, i);
		poly_ntt(ws->v[i]);
	}
	for (i = 0; i < MLKEM_K; i++) {
		poly_cbd2(&ws->k, ws->w[i], sigma, MLKEM_K + i);
		poly_ntt(ws->w[i]);
	}
	for (i = 0; i < MLKEM_K; i++) {
		for (j = 0; j < MLKEM_K; j++) {
			poly_sample_ntt(&ws->k, ws->a, rho, j, i);
			poly_mul_acc(ws->w[i], ws->a, ws->v[j]);
		}
		poly_encode(ek + i * MLKEM_POLY_BYTES, ws->w[i], 12);
		poly_encode(pke_dk + i * MLKEM_POLY_BYTES, ws->v[i], 12);
	}
	memcpy(ek + MLKEM_PKE_DK_LEN, rho, 32);
}

/* Algorithm 14, K-PKE.Encrypt, of ws->m with randomness r. */
static void kpke_encrypt(struct mlkem_ws *ws, u8 *ct, const u8 *ek,
			 const u8 r[32])
{
	const u8 *rho = ek + MLKEM_PKE_DK_LEN;
	unsigned int i, j;

	for (i = 0; i < MLKEM_K; i++) {
		poly_decode12(ws->v[i], ek + i * MLKEM_POLY_BYTES);
		poly_cbd2(&ws->k, ws->w[i], r, i);
		poly_ntt(ws->w[i]);
	}
	/* u = NTT^-1(Âᵀ ∘ ŷ) + e1 */
	for (i = 0; i < MLKEM_K; i++) {
		memset(ws->acc, 0, sizeof(ws->acc));
		for (j = 0; j < MLKEM_K; j++) {
			poly_sample_ntt(&ws->k, ws->a, rho, i, j);
			poly_mul_acc(ws->acc, ws->a, ws->w[j]);
		}
		poly_invntt(ws->acc);
		poly_cbd2(&ws->k, ws->e, r, MLKEM_K + i);
		poly_add(ws->acc, ws->e);
		poly_compress(ws->acc, MLKEM_DU);
		poly_encode(ct + i * MLKEM_U_BYTES, ws->acc, MLKEM_DU);
	}
	/* v = NTT^-1(t̂ᵀ ∘ ŷ) + e2 + Decompress_1(m) */
	memset(ws->acc, 0, sizeof(ws->acc));
	for (i = 0; i < MLKEM_K; i++)
		poly_mul_acc(ws->acc, ws->v[i], ws->w[i]);
	poly_invntt(ws->acc);
	poly_cbd2(&ws->k, ws->e, r, 2 * MLKEM_K);
	poly_add(ws->acc, ws->e);
	poly_decode(ws->e, ws->m, 1);
	poly_decompress(ws->e, 1);
	poly_add(ws->acc, ws->e);
	poly_compress(ws->acc, MLKEM_DV);
	poly_encode(ct + MLKEM_K * MLKEM_U_BYTES, ws->acc, MLKEM_DV);
}

/* Algorithm 15, K-PKE.Decrypt, into ws->m. */
static void kpke_decrypt(struct mlkem_ws *ws, const u8 *pke_dk, const u8 *ct)
{
	unsigned int i, j;

	memset(ws->acc, 0, sizeof(ws->acc));
	for (i = 0; i < MLKEM_K; i++) {
		poly_decode(ws->w[i], ct + i * MLKEM_U_BYTES, MLKEM_DU);
		poly_decompress(ws->w[i], MLKEM_DU);
		poly_ntt(ws->w[i]);
		poly_decode12(ws->v[i], pke_dk + i * MLKEM_POLY_BYTES);
		poly_mul_acc(ws->acc, ws->v[i], ws->w[i]);
	}
	poly_invntt(ws->acc);
	poly_decode(ws->e, ct + MLKEM_K * MLKEM_U_BYTES, MLKEM_DV);
	poly_decompress(ws->e, MLKEM_DV);
	for (j = 0; j < MLKEM_N; j++)
		ws->e[j] = mod_q(ws->e[j] + MLKEM_Q - ws->acc[j]);
	poly_compress(ws->e, 1);
	poly_encode(ws->m, ws->e, 1);
}

/* Algorithm 16, ML-KEM.KeyGen_internal. */
int tswg_mlkem768_keygen_seed(u8 ek[TSWG_MLKEM768_EK_LEN],
			      u8 dk[TSWG_MLKEM768_DK_LEN],
			      const u8 seed[TSWG_MLKEM768_SEED_LEN])
{
	struct mlkem_ws *ws = mlkem_ws_alloc();
	u8 *p = dk + MLKEM_PKE_DK_LEN;

	if (!ws)
		return -ENOMEM;
	kpke_keygen(ws, ek, dk, seed);
	/* dk = pke_dk || ek || H(ek) || z */
	memcpy(p, ek, TSWG_MLKEM768_EK_LEN);
	p += TSWG_MLKEM768_EK_LEN;
	mlkem_h(ws, p, ek, TSWG_MLKEM768_EK_LEN);
	memcpy(p + 32, seed + 32, 32);
	mlkem_ws_free(ws);
	return 0;
}

/* Algorithm 19, ML-KEM.KeyGen. */
int tswg_mlkem768_keygen(u8 ek[TSWG_MLKEM768_EK_LEN],
			 u8 dk[TSWG_MLKEM768_DK_LEN])
{
	u8 seed[TSWG_MLKEM768_SEED_LEN];
	int ret;

	get_random_bytes(seed, sizeof(seed));
	ret = tswg_mlkem768_keygen_seed(ek, dk, seed);
	memzero_explicit(seed, sizeof(seed));
	return ret;
}

/*
 * mlkem_ek_valid is the modulus check of section 7.2: every coefficient
 * of ek's t̂ must already be reduced.
 */
static bool mlkem_ek_valid(struct mlkem_ws *ws, const u8 *ek)
{
	unsigned int i, j;

	for (i = 0; i < MLKEM_K; i++) {
		poly_decode(ws->a, ek + i * MLKEM_POLY_BYTES, 12);
		for (j = 0; j < MLKEM_N; j++)
			if (ws->a[j] >= MLKEM_Q)
				return false;
	}
	return true;
}

/* Algorithms 17 and 20, ML-KEM.Encaps(_internal). */
int tswg_mlkem768_encaps(u8 ct[TSWG_MLKEM768_CT_LEN],
			 u8 ss[TSWG_MLKEM768_SS_LEN],
			 const u8 ek[TSWG_MLKEM768_EK_LEN])
{
	struct mlkem_ws *ws = mlkem_ws_alloc();
	u8 h[32];

	if (!ws)
		return -ENOMEM;
	if (!mlkem_ek_valid(ws, ek)) {
		mlkem_ws_free(ws);
		return -EINVAL;
	}
	get_random_bytes(ws->m, sizeof(ws->m));
	mlkem_h(ws, h, ek, TSWG_MLKEM768_EK_LEN);
	mlkem_g(ws, ws->m, 32, h, 32);
	memcpy(ss, ws->g, 32);
	kpke_encrypt(ws, ct, ek, ws->g + 32);
	mlkem_ws_free(ws);
	return 0;
}

/*
 * Algorithms 18 and 21, ML-KEM.Decaps(_internal). dk is our own, so it
 * skips the input checks of section 7.3.
 */
int tswg_mlkem768_decaps(u8 ss[TSWG_MLKEM768_SS_LEN],
			 const u8 ct[TSWG_MLKEM768_CT_LEN],
			 const u8 dk[TSWG_MLKEM768_DK_LEN])
{
	const u8 *ek = dk + MLKEM_PKE_DK_LEN;
	const u8 *h = ek + TSWG_MLKEM768_EK_LEN, *z = h + 32;
	struct mlkem_ws *ws = mlkem_ws_alloc();
	u8 reject[32], mask;
	unsigned int i;

	if (!ws)
		return -ENOMEM;
	kpke_decrypt(ws, dk, ct);
	mlkem_g(ws, ws->m, 32, h, 32);
	keccak2(&ws->k, SHAKE256_RATE, SHAKE_DS, z, 32, ct,
		TSWG_MLKEM768_CT_LEN, reject, sizeof(reject));
	kpke_encrypt(ws, ws->ct, ek, ws->g + 32);
	/* Implicit rejection: K̄ unless the ciphertext re-encrypts. */
	mask = -(u8)!!crypto_memneq(ct, ws->ct, TSWG_MLKEM768_CT_LEN);
	for (i = 0; i < 32; i++)
		ss[i] = ws->g[i] ^ (mask & (ws->g[i] ^ reject[i]));
	memzero_explicit(reject, sizeof(reject));
	mlkem_ws_free(ws);
	return 0;
}
