/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TSWG: ML-KEM-768 (FIPS 203), for hybrid post-quantum handshakes; see
 * mlkem.c.
 */

#ifndef _TSWG_MLKEM_H
#define _TSWG_MLKEM_H

#include <linux/types.h>

enum tswg_mlkem768_lengths {
	TSWG_MLKEM768_EK_LEN = 1184, /* encapsulation (public) key */
	TSWG_MLKEM768_DK_LEN = 2400, /* decapsulation (private) key */
	TSWG_MLKEM768_CT_LEN = 1088, /* ciphertext */
	TSWG_MLKEM768_SS_LEN = 32, /* shared secret */
	TSWG_MLKEM768_SEED_LEN = 64 /* d || z, as in Go's crypto/mlkem */
};

void tswg_mlkem_init(void);

/*
 * The functions below return 0 or a negative errno: -ENOMEM, or -EINVAL
 * for an encapsulation key that isn't valid. They may sleep.
 */
int tswg_mlkem768_keygen(u8 ek[TSWG_MLKEM768_EK_LEN],
			 u8 dk[TSWG_MLKEM768_DK_LEN]);
int tswg_mlkem768_keygen_seed(u8 ek[TSWG_MLKEM768_EK_LEN],
			      u8 dk[TSWG_MLKEM768_DK_LEN],
			      const u8 seed[TSWG_MLKEM768_SEED_LEN]);
int tswg_mlkem768_encaps(u8 ct[TSWG_MLKEM768_CT_LEN],
			 u8 ss[TSWG_MLKEM768_SS_LEN],
			 const u8 ek[TSWG_MLKEM768_EK_LEN]);
int tswg_mlkem768_decaps(u8 ss[TSWG_MLKEM768_SS_LEN],
			 const u8 ct[TSWG_MLKEM768_CT_LEN],
			 const u8 dk[TSWG_MLKEM768_DK_LEN]);

#endif /* _TSWG_MLKEM_H */
