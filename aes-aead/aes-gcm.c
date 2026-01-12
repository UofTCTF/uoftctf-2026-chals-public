#include <string.h>

#include "aes-gcm.h"

#define WPA_GET_BE32(a) ((((uint32_t) (a)[0]) << 24) | (((uint32_t) (a)[1]) << 16) | \
			 (((uint32_t) (a)[2]) << 8) | ((uint32_t) (a)[3]))

#define WPA_PUT_BE32(a, val)					\
	do {							\
		(a)[0] = (uint8_t) ((((uint32_t) (val)) >> 24) & 0xff);	\
		(a)[1] = (uint8_t) ((((uint32_t) (val)) >> 16) & 0xff);	\
		(a)[2] = (uint8_t) ((((uint32_t) (val)) >> 8) & 0xff);	\
		(a)[3] = (uint8_t) (((uint32_t) (val)) & 0xff);		\
	} while (0)

#define WPA_GET_BE64(a) ((((uint64_t) (a)[0]) << 56) | (((uint64_t) (a)[1]) << 48) | \
			 (((uint64_t) (a)[2]) << 40) | (((uint64_t) (a)[3]) << 32) | \
			 (((uint64_t) (a)[4]) << 24) | (((uint64_t) (a)[5]) << 16) | \
			 (((uint64_t) (a)[6]) << 8) | ((uint64_t) (a)[7]))
#define WPA_PUT_BE64(a, val)				\
	do {						\
		(a)[0] = (uint8_t) (((uint64_t) (val)) >> 56);	\
		(a)[1] = (uint8_t) (((uint64_t) (val)) >> 48);	\
		(a)[2] = (uint8_t) (((uint64_t) (val)) >> 40);	\
		(a)[3] = (uint8_t) (((uint64_t) (val)) >> 32);	\
		(a)[4] = (uint8_t) (((uint64_t) (val)) >> 24);	\
		(a)[5] = (uint8_t) (((uint64_t) (val)) >> 16);	\
		(a)[6] = (uint8_t) (((uint64_t) (val)) >> 8);	\
		(a)[7] = (uint8_t) (((uint64_t) (val)) & 0xff);	\
	} while (0)

static void inc32(uint8_t *block)
{
	uint32_t val;
	val = WPA_GET_BE32(block + AES_BLOCK_SIZE - 4);
	val++;
	WPA_PUT_BE32(block + AES_BLOCK_SIZE - 4, val);
}


static void xor_block(uint8_t *dst, const uint8_t *src)
{
	uint32_t *d = (uint32_t *) dst;
	uint32_t *s = (uint32_t *) src;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
}


static void shift_right_block(uint8_t *v)
{
	uint32_t val;

	val = WPA_GET_BE32(v + 12);
	val >>= 1;
	if (v[11] & 0x01)
		val |= 0x80000000;
	WPA_PUT_BE32(v + 12, val);

	val = WPA_GET_BE32(v + 8);
	val >>= 1;
	if (v[7] & 0x01)
		val |= 0x80000000;
	WPA_PUT_BE32(v + 8, val);

	val = WPA_GET_BE32(v + 4);
	val >>= 1;
	if (v[3] & 0x01)
		val |= 0x80000000;
	WPA_PUT_BE32(v + 4, val);

	val = WPA_GET_BE32(v);
	val >>= 1;
	WPA_PUT_BE32(v, val);
}


/* Multiplication in GF(2^128) */
static void gf_mult(const uint8_t *x, const uint8_t *y, uint8_t *z)
{
	uint8_t v[16];
	int i, j;

	memset(z, 0, 16); /* Z_0 = 0^128 */
	memcpy(v, y, 16); /* V_0 = Y */

	for (i = 0; i < 16; i++) {
		for (j = 0; j < 8; j++) {
			if (x[i] & (1 << (7 - j))) {
				/* Z_(i + 1) = Z_i XOR V_i */
				xor_block(z, v);
			} else {
				/* Z_(i + 1) = Z_i */
			}

			if (v[15] & 0x01) {
				/* V_(i + 1) = (V_i >> 1) XOR R */
				shift_right_block(v);
				/* R = 11100001 || 0^120 */
				v[0] ^= 0xe1;
			} else {
				/* V_(i + 1) = V_i >> 1 */
				shift_right_block(v);
			}
		}
	}
}


static void ghash_start(uint8_t *y)
{
	/* Y_0 = 0^128 */
	memset(y, 0, 16);
}


static void ghash(const uint8_t *h, const uint8_t *x, size_t xlen, uint8_t *y)
{
	size_t m, i;
	const uint8_t *xpos = x;
	uint8_t tmp[16];

	m = xlen / 16;

	for (i = 0; i < m; i++) {
		/* dot operation:
		 * multiplication operation for binary Galois (finite) field of
		 * 2^128 elements */
		gf_mult(y, h, tmp);
        /* Y_i = (Y^(i-1) XOR X_i) dot H */
		xor_block(tmp, xpos);
		xpos += 16;
		memcpy(y, tmp, 16);
	}

	if (x + xlen > xpos) {


		/* dot operation:
		 * multiplication operation for binary Galois (finite) field of
		 * 2^128 elements */
		gf_mult(y, h, tmp);

        		/* Add zero padded last block */
		size_t last = x + xlen - xpos;
		memcpy(y, xpos, last);
		memset(y + last, 0, sizeof(tmp) - last);

		xor_block(y, tmp);
	}

	/* Return Y_m */
}


static void aes_gctr(const uint8_t *key, const uint8_t *icb, const uint8_t *x, size_t xlen, uint8_t *y)
{
	size_t i, n, last;
	uint8_t cb[AES_BLOCK_SIZE], tmp[AES_BLOCK_SIZE];
	const uint8_t *xpos = x;
	uint8_t *ypos = y;

	if (xlen == 0)
		return;

	n = xlen / 16;

	memcpy(cb, icb, AES_BLOCK_SIZE);
	/* Full blocks */
	for (i = 0; i < n; i++) {
		aes_encrypt(key, cb, ypos);
		xor_block(ypos, xpos);
		xpos += AES_BLOCK_SIZE;
		ypos += AES_BLOCK_SIZE;
		inc32(cb);
	}

	last = x + xlen - xpos;
	if (last) {
		/* Last, partial block */
		aes_encrypt(key, cb, tmp);
		for (i = 0; i < last; i++)
			*ypos++ = *xpos++ ^ tmp[i];
	}
}


static void aes_aead_init_hash_subkey(const uint8_t *key, size_t key_len, uint8_t *H)
{
	/* Generate hash subkey H = AES_K(0^128) */
	memset(H, 0, AES_BLOCK_SIZE);
	aes_encrypt(key, H, H);
}


static void aes_aead_prepare_j0(const uint8_t *iv, size_t iv_len, const uint8_t *H, uint8_t *J0)
{
	uint8_t len_buf[16];

	if (iv_len == 12) {
		/* Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96] */
		memcpy(J0, iv, iv_len);
		memset(J0 + iv_len, 0, AES_BLOCK_SIZE - iv_len);
		J0[AES_BLOCK_SIZE - 1] = 0x01;
	} else {
		/*
		 * s = 128 * ceil(len(IV)/128) - len(IV)
		 * J_0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64)
		 */
		ghash_start(J0);
		ghash(H, iv, iv_len, J0);
		WPA_PUT_BE64(len_buf, 0);
		WPA_PUT_BE64(len_buf + 8, iv_len * 8);
		ghash(H, len_buf, sizeof(len_buf), J0);
	}
}


static void aes_aead_gctr(const uint8_t *key, const uint8_t *J0, const uint8_t *in, size_t len,
			 uint8_t *out)
{
	uint8_t J0inc[AES_BLOCK_SIZE];

	if (len == 0)
		return;

	memcpy(J0inc, J0, AES_BLOCK_SIZE);
	inc32(J0inc);
	aes_gctr(key, J0inc, in, len, out);
}


static void aes_aead_ghash(const uint8_t *H, const uint8_t *aad, size_t aad_len,
			  const uint8_t *crypt, size_t crypt_len, uint8_t *S)
{
	uint8_t len_buf[16];

	/*
	 * u = 128 * ceil[len(C)/128] - len(C)
	 * v = 128 * ceil[len(A)/128] - len(A)
	 * S = GHASH_H(A || 0^v || C || 0^u || [len(A)]64 || [len(C)]64)
	 * (i.e., zero padded to block size A || C and lengths of each in bits)
	 */
	ghash_start(S);
	ghash(H, aad, aad_len, S);
	ghash(H, crypt, crypt_len, S);
	WPA_PUT_BE64(len_buf, aad_len * 8);
	WPA_PUT_BE64(len_buf + 8, crypt_len * 8);
	ghash(H, len_buf, sizeof(len_buf), S);
}


/**
 * aes_aead_ae - aead-AE_K(IV, P, A)
 */
int aes_aead_ae(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
	       const uint8_t *plain, size_t plain_len,
	       const uint8_t *aad, size_t aad_len, uint8_t *crypt, uint8_t *tag)
{
	uint8_t H[AES_BLOCK_SIZE];
	uint8_t J0[AES_BLOCK_SIZE];
	uint8_t S[16];

    aes_aead_init_hash_subkey(key, key_len, H);

	aes_aead_prepare_j0(iv, iv_len, H, J0);

	/* C = GCTR_K(inc_32(J_0), P) */
	aes_aead_gctr(key, J0, plain, plain_len, crypt);

	aes_aead_ghash(H, aad, aad_len, crypt, plain_len, S);

	/* T = MSB_t(GCTR_K(J_0, S)) */
	aes_gctr(key, J0, S, sizeof(S), tag);

	/* Return (C, T) */

	return 0;
}


/**
 * aes_aead_ad - aead-AD_K(IV, C, A, T)
 */
int aes_aead_ad(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
	       const uint8_t *crypt, size_t crypt_len,
	       const uint8_t *aad, size_t aad_len, const uint8_t *tag, uint8_t *plain)
{
	uint8_t H[AES_BLOCK_SIZE];
	uint8_t J0[AES_BLOCK_SIZE];
	uint8_t S[16], T[16];

	aes_aead_init_hash_subkey(key, key_len, H);

	aes_aead_prepare_j0(iv, iv_len, H, J0);

	aes_aead_ghash(H, aad, aad_len, crypt, crypt_len, S);

	/* T' = MSB_t(GCTR_K(J_0, S)) */
	aes_gctr(key, J0, S, sizeof(S), T);

	if (memcmp(tag, T, 16) != 0) {
		return -1;
	}

	/* P = GCTR_K(inc_32(J_0), C) */
	aes_aead_gctr(key, J0, crypt, crypt_len, plain);

	return 0;
}


int aes_gmac(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
	     const uint8_t *aad, size_t aad_len, uint8_t *tag)
{
	return aes_aead_ae(key, key_len, iv, iv_len, NULL, 0, aad, aad_len, NULL,
			  tag);
}