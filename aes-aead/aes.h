#include <stdlib.h>
#include <stdint.h>

#define AES_BLOCK_SIZE 16

// expects 16 byte of key and 16 byte of msg and 16 byte space for enc
void aes_encrypt(const u_int8_t *key, const u_int8_t *msg, u_int8_t *enc);
void aes_decrypt(const u_int8_t *key, const u_int8_t *enc, u_int8_t *msg);
