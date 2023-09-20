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

// Source: https://t.me/c/1147847827/52532
EMSCRIPTEN_KEEPALIVE
void factorize(int64_t pq, int64_t out[2]) {
    int64_t pqSqrt = (int64_t)sqrtl((long double)pq), ySqr, y, p, q;
    while (pqSqrt * pqSqrt > pq)
        --pqSqrt;
    while (pqSqrt * pqSqrt < pq)
        ++pqSqrt;
    for (ySqr = pqSqrt * pqSqrt - pq;; ++pqSqrt, ySqr = pqSqrt * pqSqrt - pq) {
        y = (int64_t)sqrtl((long double)ySqr);
        while (y * y > ySqr)
            --y;
        while (y * y < ySqr)
            ++y;

        if (!ySqr || y + pqSqrt >= pq) {
            out[0] = -1;
            out[1] = -1;
            return;
        }

        if (y * y == ySqr) {
            p = pqSqrt + y;
            q = (pqSqrt > y) ? (pqSqrt - y) : (y - pqSqrt);
            break;
        }
    }

    if (p > q) {
        out[0] = q;
        out[1] = p;
    } else {
        out[0] = p;
        out[1] = q;
    }
}
