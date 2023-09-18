#include <math.h>
#include <stdexcept>
#include <vector>

#include <emscripten/bind.h>
#include <emscripten/val.h>

extern "C" {
#include <aes256.h>
#include <cbc256.h>
#include <ctr256.h>
#include <ige256.h>
}

using namespace emscripten;

val ige(std::string data, std::string key, std::string iv, bool encrypt) {
    if (data.length() == 0) {
        throw std::length_error("data must not be empty");
    }
    if (data.length() % 16 != 0) {
        throw std::length_error("data size must be divisible by 16");
    }
    if (key.length() != 32) {
        throw std::length_error("key must be 32 bytes");
    }
    if (iv.length() != 32) {
        throw std::length_error("iv must be 32 bytes");
    }

    auto out =
        ige256(reinterpret_cast<const uint8_t*>(data.c_str()), data.length(),
               reinterpret_cast<const uint8_t*>(key.c_str()),
               reinterpret_cast<const uint8_t*>(iv.c_str()), encrypt);

    std::vector<uint8_t> outv(data.length());
    memcpy(outv.data(), &out[0], data.length());
    free(out);

    return val(outv);
}

val ige256_encrypt(std::string data, std::string key, std::string iv) {
    return ige(data, key, iv, true);
}

val ige256_decrypt(std::string data, std::string key, std::string iv) {
    return ige(data, key, iv, false);
}

val ctr256_encrypt(std::string data,
                   val set,
                   std::string key,
                   std::string iv,
                   std::string state) {
    if (data.length() == 0) {
        throw std::length_error("data must not be empty");
    }
    if (key.length() != 32) {
        throw std::length_error("key must be 32 bytes");
    }
    if (iv.length() != 16) {
        throw std::length_error("iv must be 16 bytes");
    }
    if (state.length() != 1) {
        throw std::length_error("state must be 1 byte");
    }
    if (state[0] > 15) {
        throw std::range_error("state must be in the range 0..15");
    }

    std::vector<uint8_t> ivp(16);
    memcpy(ivp.data(), &iv[0], 16);

    std::vector<uint8_t> statep(1);
    memcpy(statep.data(), &state[0], 1);

    ctr256(reinterpret_cast<uint8_t*>(data.data()), data.length(),
           reinterpret_cast<const uint8_t*>(key.c_str()), ivp.data(),
           statep.data());

    set.call<void>("set", typed_memory_view(data.length(), data.data()));

    std::vector<val> result;

    result.push_back(val(ivp));
    result.push_back(val(statep));

    return val::array(result);
}

void cbc(std::string data,
        val set,
        std::string key,
        std::string iv,
        bool encrypt) {
    if (data.length() == 0) {
        throw std::length_error("data must not be empty");
    }
    if (data.length() % 16 != 0) {
        throw std::length_error("data size must be divisible by 16");
    }
    if (key.length() != 32) {
        throw std::length_error("key must be 32 bytes");
    }
    if (iv.length() != 16) {
        throw std::length_error("iv must be 16 bytes");
    }

    cbc256(reinterpret_cast<const uint8_t*>(data.data()), data.length(),
           reinterpret_cast<const uint8_t*>(key.c_str()),
           (uint8_t*)(iv.c_str()), encrypt);

    set.call<void>("set", typed_memory_view(data.length(), data.data()));
}

void cbc256_encrypt(std::string data, val set, std::string key, std::string iv) {
    cbc(data, set, key, iv, true);
}

void cbc256_decrypt(std::string data, val set, std::string key, std::string iv) {
    cbc(data, set, key, iv, false);
}

// Source: https://t.me/c/1147847827/52532
val factorize(int64_t pq) {
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
            std::vector<int64_t> result = {-1, -1};
            return val(result);
        }

        if (y * y == ySqr) {
            p = pqSqrt + y;
            q = (pqSqrt > y) ? (pqSqrt - y) : (y - pqSqrt);
            break;
        }
    }

    if (p > q)
        std::swap(p, q);

    std::vector<int64_t> result = {p, q};
    return val(result);
}

EMSCRIPTEN_BINDINGS(my_module) {
    register_vector<uint8_t>("vector<uint8_t>");
    register_vector<int64_t>("vector<int64_t>");

    function("ige256Encrypt", &ige256_encrypt);
    function("ige256Decrypt", &ige256_decrypt);
    function("ctr256Encrypt", &ctr256_encrypt);
    function("ctr256Decrypt", &ctr256_encrypt);
    function("cbc256Encrypt", &cbc256_encrypt);
    function("cbc256Decrypt", &cbc256_decrypt);
    function("factorize", &factorize);
}
