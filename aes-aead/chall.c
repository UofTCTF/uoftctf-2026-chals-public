#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>

#include "aes-gcm.h"

#define NUM_TEXTS 0x10
#define BUF_SZ 0x178

typedef struct {
    uint8_t buf[BUF_SZ];
    size_t len;
} Text;
_Static_assert(sizeof(Text) % 0x10 == 0, "Text size");

Text *texts[NUM_TEXTS] = {0};

int setup(){
    setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);
}

void menu(){
    printf("1. Create Text\n2. Read Text\n3. Encrypt Text\n4. Decrypt Text\n5. Delete Text\n6. Exit\n");
}

int get_num(){
    int result;
    scanf("%d", &result);
    while (getchar() != '\n');
    return result;
}

static inline int get_text_idx(){
    int result = get_num();
    if (result < 0 || result >= NUM_TEXTS)
        exit(1);
    return result;
}

void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
}

static uint8_t hex_to_byte(uint8_t high, uint8_t low) {
    int hi = isdigit(high) ? high - '0' : toupper(high) - 'A' + 10;
    int lo = isdigit(low) ? low - '0' : toupper(low) - 'A' + 10;
    return (uint8_t)((hi << 4) | lo);
}


uint8_t *read_hex_as_bytes(size_t *out_len) {
    uint8_t *hex = NULL;
    size_t bufsize = 0;

    if (getline(&hex, &bufsize, stdin) == -1) {
        free(hex);
        return NULL;
    }

    // Strip newline
    hex[strcspn(hex, "\n")] = '\0';

    size_t hex_len = strlen(hex);

    // Hex length must be even
    if (hex_len % 2 != 0) {
        memset(hex, 0, bufsize);
        free(hex);
        return NULL;
    }

    size_t bytes_len = hex_len / 2;
    uint8_t *bytes = malloc(bytes_len);
    if (!bytes) {
        memset(hex, 0, bufsize);
        free(hex);
        return NULL;
    }

    // Convert hex → bytes
    for (size_t i = 0; i < bytes_len; i++) {
        uint8_t h = hex[2*i];
        uint8_t l = hex[2*i + 1];

        if (!isxdigit(h) || !isxdigit(l)) {
            memset(hex, 0, bufsize);
            memset(bytes, 0, bytes_len);
            free(hex);
            free(bytes);
            return NULL;
        }

        bytes[i] = hex_to_byte(h, l);
    }
    memset(hex, 0, bufsize);
    free(hex);
    *out_len = bytes_len;
    return bytes;
}

void encrypt_text(uint8_t *key, Text *data){
    uint8_t* dat = data;
    
    for (size_t i = 0; i < sizeof(Text); i+=0x10)
    {
        aes_encrypt(key, dat + i, dat + i);
    }
}

void decrypt_text(uint8_t *key, Text *data){
    uint8_t* dat = data;
    
    for (size_t i = 0; i < sizeof(Text); i+=0x10)
    {
        aes_decrypt(key, dat + i, dat + i);
    }
}

int main(){
    setup();

    uint8_t *key = malloc(AES_BLOCK_SIZE);
    int randfd = open("/dev/urandom", O_RDONLY);
    if (randfd == -1){
        perror("Error getting random: ");
        exit(1);
    }

    int err = read(randfd, key, 16);
    if (err == -1){
        perror("Error getting random: ");
        exit(1);
    }

    int repeat = 1;
    int res;
    size_t idx, sz;
    uint8_t iv[AES_BLOCK_SIZE], tag[AES_BLOCK_SIZE];
    uint8_t *ct;

    while (repeat)
    {
        menu();
        printf("> ");
        int choice = get_num();
        switch (choice)
        {
        case 1:
            printf("Index: ");
            idx = get_text_idx();
            if (texts[idx] != NULL){
                printf("That index has been used\n");
                break;
            }

            texts[idx] = malloc(sizeof(Text));
            texts[idx]->len = read(STDIN_FILENO, texts[idx]->buf, BUF_SZ);
            encrypt_text(key, texts[idx]);
            break;
        case 2:
            printf("Index: ");
            idx = get_text_idx();
            if (texts[idx] == NULL){
                printf("That index is empty\n");
                break;
            }
            printf("Text: ");
            decrypt_text(key, texts[idx]);
            write(STDOUT_FILENO, texts[idx]->buf, texts[idx]->len);
            encrypt_text(key, texts[idx]);
            printf("\n");
            break;
        case 3:
            printf("Index: ");
            idx = get_text_idx();
            if (texts[idx] == NULL){
                printf("That index is empty\n");
                break;
            }
            decrypt_text(key, texts[idx]);
            printf("Ciphertext: ");
            ct = malloc(texts[idx]->len);
            read(randfd, iv, AES_BLOCK_SIZE);

            aes_aead_ae(key, AES_BLOCK_SIZE, iv, AES_BLOCK_SIZE, texts[idx]->buf, texts[idx]->len, "", 0, ct, tag);

            print_hex(tag, AES_BLOCK_SIZE);
            print_hex(iv, AES_BLOCK_SIZE);
            print_hex(ct, texts[idx]->len);
            printf("\n");

            free(ct);
            encrypt_text(key, texts[idx]);
            break;
        
        case 4:
            printf("Index: ");
            idx = get_text_idx();
            if (texts[idx] != NULL){
                printf("That index has been used\n");
                break;
            }

            printf("Ciphertext: ");

            ct = read_hex_as_bytes(&sz);

            if (ct == NULL || sz <= 32){
                printf("Error\n");
                if (ct != NULL)
                    free(ct);
                break;
            }

            texts[idx] = malloc(sizeof(Text));
            texts[idx]->len = sz - (AES_BLOCK_SIZE * 2);
            res = aes_aead_ad(key, AES_BLOCK_SIZE, ct + AES_BLOCK_SIZE, AES_BLOCK_SIZE, ct + (AES_BLOCK_SIZE * 2), texts[idx]->len, "", 0, ct, texts[idx]->buf);
            if (res != 0) {
                printf("Invalid ciphertext\n");
                memset(ct, 0, sz);
                free(texts[idx]);
                texts[idx] = NULL;
                break;
            }
            memset(ct, 0, sz);
            free(ct);
            encrypt_text(key, texts[idx]);
            break;
        case 5:
            printf("Index: ");
            idx = get_text_idx();
            if (texts[idx] == NULL){
                printf("That index is empty\n");
                break;
            }
            free(texts[idx]);
            texts[idx] = NULL;
            break;
        case 6:
            repeat = 0;
            break;
        default:
            printf("That is not an option\n");
            break;
        }
    }
}