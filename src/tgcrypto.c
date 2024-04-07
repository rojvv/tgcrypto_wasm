#include <aes256.h>
#include <cbc256.h>
#include <ctr256.h>
#include <emscripten/emscripten.h>
#include <ige256.h>
#include <math.h>

EMSCRIPTEN_KEEPALIVE
void ige256_encrypt(const uint8_t in[],
                    uint8_t out[],
                    uint32_t length,
                    const uint8_t key[32],
                    const uint8_t iv[32]) {
    tgcrypto_ige256(in, out, length, key, iv, 1);
}

EMSCRIPTEN_KEEPALIVE
void ige256_decrypt(const uint8_t in[],
                    uint8_t out[],
                    uint32_t length,
                    const uint8_t key[32],
                    const uint8_t iv[32]) {
    tgcrypto_ige256(in, out, length, key, iv, 0);
}

EMSCRIPTEN_KEEPALIVE
void ctr256(uint8_t in[],
            uint32_t length,
            const uint8_t key[32],
            uint8_t iv[16],
            uint8_t state[1]) {
    tgcrypto_ctr256(in, length, key, iv, state);
}

EMSCRIPTEN_KEEPALIVE
void cbc256_encrypt(uint8_t in[],
                    uint32_t length,
                    const uint8_t key[32],
                    const uint8_t iv[16]) {
    tgcrypto_cbc256(in, length, key, iv, 1);
}

EMSCRIPTEN_KEEPALIVE
void cbc256_decrypt(uint8_t in[],
                    uint32_t length,
                    const uint8_t key[32],
                    const uint8_t iv[16]) {
    tgcrypto_cbc256(in, length, key, iv, 0);
}
