// SPDX-License-Identifier: GPL-2.0
/*
 * driver runs src/mlkem.c in userspace for mlkem_test.go. It reads
 * commands, one per line, with arguments in hex, and writes each result
 * as a line of space-separated hex, or "err":
 *
 *	keygen SEED     -> EK DK
 *	encaps EK       -> CT SS
 *	decaps DK CT    -> SS
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../src/mlkem.c"

static int unhex(u8 *dst, size_t n, const char *s)
{
	size_t i;

	if (strlen(s) != 2 * n)
		return -1;
	for (i = 0; i < n; i++)
		if (sscanf(s + 2 * i, "%2hhx", &dst[i]) != 1)
			return -1;
	return 0;
}

static void puthex(const u8 *p, size_t n)
{
	while (n--)
		printf("%02x", *p++);
}

int main(void)
{
	static u8 ek[TSWG_MLKEM768_EK_LEN], dk[TSWG_MLKEM768_DK_LEN];
	static u8 ct[TSWG_MLKEM768_CT_LEN], ss[TSWG_MLKEM768_SS_LEN];
	static u8 seed[TSWG_MLKEM768_SEED_LEN];
	static char line[16384];
	char *cmd, *a, *b;

	setvbuf(stdout, NULL, _IOLBF, 0);
	tswg_mlkem_init();
	while (fgets(line, sizeof(line), stdin)) {
		line[strcspn(line, "\n")] = 0;
		cmd = strtok(line, " ");
		a = strtok(NULL, " ");
		b = strtok(NULL, " ");
		if (!cmd || !a) {
			puts("err");
		} else if (!strcmp(cmd, "keygen")) {
			if (unhex(seed, sizeof(seed), a) ||
			    tswg_mlkem768_keygen_seed(ek, dk, seed)) {
				puts("err");
				continue;
			}
			puthex(ek, sizeof(ek));
			putchar(' ');
			puthex(dk, sizeof(dk));
			putchar('\n');
		} else if (!strcmp(cmd, "encaps")) {
			if (unhex(ek, sizeof(ek), a) ||
			    tswg_mlkem768_encaps(ct, ss, ek)) {
				puts("err");
				continue;
			}
			puthex(ct, sizeof(ct));
			putchar(' ');
			puthex(ss, sizeof(ss));
			putchar('\n');
		} else if (!strcmp(cmd, "decaps") && b) {
			if (unhex(dk, sizeof(dk), a) || unhex(ct, sizeof(ct), b) ||
			    tswg_mlkem768_decaps(ss, ct, dk)) {
				puts("err");
				continue;
			}
			puthex(ss, sizeof(ss));
			putchar('\n');
		} else {
			puts("err");
		}
	}
	return 0;
}
