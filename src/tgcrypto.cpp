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

    uint8_t datap[data.length()];
    data.copy((char*)datap, data.length());

    uint8_t keyp[32];
    key.copy((char*)keyp, 32);

    uint8_t ivp[16];
    iv.copy((char*)ivp, 16);

    uint8_t* out = ige256(datap, data.length(), keyp, ivp, encrypt);

    free(keyp);
    free(ivp);

    return val(typed_memory_view(data.length(), out));
}

val ige256_encrypt(std::string data, std::string key, std::string iv) {
    return ige(data, key, iv, true);
}

val ige256_decrypt(std::string data, std::string key, std::string iv) {
    return ige(data, key, iv, false);
}

val ctr256_encrypt(std::string data,
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

    uint8_t datap[data.length()];
    data.copy((char*)datap, data.length());

    uint8_t keyp[32];
    key.copy((char*)keyp, 32);

    uint8_t ivp[16];
    iv.copy((char*)ivp, 16);

    uint8_t statep[1];
    state.copy((char*)statep, 1);

    uint8_t* out = ctr256(datap, data.length(), keyp, ivp, statep);

    free(keyp);
    free(datap);

    std::vector<memory_view<uint8_t>> result;

    result.push_back(typed_memory_view(data.length(), out));
    result.push_back(typed_memory_view(16, ivp));
    result.push_back(typed_memory_view(1, statep));

    return val::array(result);
}

val cbc(std::string data, std::string key, std::string iv, bool encrypt) {
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

    uint8_t datap[data.length()];
    data.copy((char*)datap, data.length());

    uint8_t keyp[32];
    key.copy((char*)keyp, 32);

    uint8_t ivp[16];
    iv.copy((char*)ivp, 16);

    uint8_t* out = cbc256(datap, data.length(), keyp, ivp, encrypt);

    free(keyp);
    free(ivp);

    return val(typed_memory_view(data.length(), out));
}

val cbc256_encrypt(std::string data, std::string key, std::string iv) {
    return cbc(data, key, iv, true);
}

val cbc256_decrypt(std::string data, std::string key, std::string iv) {
    return cbc(data, key, iv, false);
}

EMSCRIPTEN_BINDINGS(my_module) {
    function("ige256Encrypt", &ige256_encrypt);
    function("ige256Decrypt", &ige256_decrypt);
    function("ctr256Encrypt", &ctr256_encrypt);
    function("ctr256Decrypt", &ctr256_encrypt);
    function("cbc256Encrypt", &cbc256_encrypt);
    function("cbc256Decrypt", &cbc256_decrypt);
}
