#include <emscripten/val.h>

#ifndef CTR256_H
#define CTR256_H

void ctr256(emscripten::val *out, uint32_t length, const uint8_t key[32], uint8_t iv[16], uint8_t *state);

#endif  // CTR256_H
