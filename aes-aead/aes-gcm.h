#include "aes.h"

int aes_aead_ae(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
	       const uint8_t *plain, size_t plain_len,
	       const uint8_t *aad, size_t aad_len, uint8_t *crypt, uint8_t *tag);

int aes_aead_ad(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
	       const uint8_t *crypt, size_t crypt_len,
	       const uint8_t *aad, size_t aad_len, const uint8_t *tag, uint8_t *plain);

