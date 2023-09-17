#include "aes256.h"

uint8_t *ige256(const uint8_t in[], uint32_t length, const uint8_t key[32], const uint8_t iv[32], uint8_t encrypt) {
    uint8_t *out = (uint8_t *) malloc(length * sizeof(uint8_t));
    uint8_t iv1[AES_BLOCK_SIZE], iv2[AES_BLOCK_SIZE];
    uint8_t chunk[AES_BLOCK_SIZE], buffer[AES_BLOCK_SIZE];
    uint32_t expandedKey[EXPANDED_KEY_SIZE];
    uint32_t i, j;

    memcpy(encrypt ? iv1 : iv2, (uint8_t *) iv, AES_BLOCK_SIZE);
    memcpy(encrypt ? iv2 : iv1, (uint8_t *) iv + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    (encrypt ? aes256_set_encryption_key : aes256_set_decryption_key)(key, expandedKey);

    for (i = 0; i < length; i += AES_BLOCK_SIZE) {
        memcpy(chunk, &in[i], AES_BLOCK_SIZE);

        for (j = 0; j < AES_BLOCK_SIZE; ++j)
            buffer[j] = in[i + j] ^ iv1[j];

        (encrypt ? aes256_encrypt : aes256_decrypt)((uint8_t * ) & buffer, &out[i], expandedKey);

        for (j = 0; j < AES_BLOCK_SIZE; ++j)
            out[i + j] ^= iv2[j];

        memcpy(iv1, &out[i], AES_BLOCK_SIZE);
        memcpy(iv2, chunk, AES_BLOCK_SIZE);
    }

    return out;
}
