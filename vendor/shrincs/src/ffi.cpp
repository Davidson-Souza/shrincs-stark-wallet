#include "shrincs.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <exception>
#include <vector>

namespace {
constexpr std::size_t FFI_N = Parameters::N;
constexpr std::size_t FFI_WOTS_SIGN_LEN = Parameters::WOTS_SIGN_LEN;
constexpr std::size_t FFI_HSF = Parameters::HSF;
constexpr std::size_t FFI_SL_SIZE = Parameters::SL_SIZE;

constexpr std::size_t FFI_STATEFUL_MIN_SIZE = FFI_N + FFI_WOTS_SIGN_LEN + FFI_N;
constexpr std::size_t FFI_STATEFUL_MAX_SIZE = FFI_N + FFI_WOTS_SIGN_LEN + FFI_HSF * FFI_N;

void set_error(char* error, std::size_t error_len, const char* message) {
    if (error == nullptr || error_len == 0) return;
    const std::size_t length = std::min(error_len - 1, std::strlen(message));
    std::memcpy(error, message, length);
    error[length] = '\0';
}

void import_pk(const std::uint8_t* bytes, SHRINCS::PublicKey& pk) {
    std::memcpy(pk.seed.data(), bytes, FFI_N);
    std::memcpy(pk.root.data(), bytes + FFI_N, FFI_N);
}

void export_pk(const SHRINCS::PublicKey& pk, std::uint8_t* bytes) {
    std::memcpy(bytes, pk.seed.data(), FFI_N);
    std::memcpy(bytes + FFI_N, pk.root.data(), FFI_N);
}

void import_sk(const std::uint8_t* bytes, SHRINCS::SecretKey& sk) {
    std::memcpy(sk.seed.data(), bytes, FFI_N);
    std::memcpy(sk.prf.data(), bytes + FFI_N, FFI_N);
    std::memcpy(sk.sf.data(), bytes + 2 * FFI_N, FFI_N);
    std::memcpy(sk.sl.data(), bytes + 3 * FFI_N, FFI_N);
    std::memcpy(sk.pk.seed.data(), bytes + 4 * FFI_N, FFI_N);
    std::memcpy(sk.pk.root.data(), bytes + 5 * FFI_N, FFI_N);
}

void export_sk(const SHRINCS::SecretKey& sk, std::uint8_t* bytes) {
    std::memcpy(bytes, sk.seed.data(), FFI_N);
    std::memcpy(bytes + FFI_N, sk.prf.data(), FFI_N);
    std::memcpy(bytes + 2 * FFI_N, sk.sf.data(), FFI_N);
    std::memcpy(bytes + 3 * FFI_N, sk.sl.data(), FFI_N);
    std::memcpy(bytes + 4 * FFI_N, sk.pk.seed.data(), FFI_N);
    std::memcpy(bytes + 5 * FFI_N, sk.pk.root.data(), FFI_N);
}
}  // namespace

extern "C" int ssw_shrincs_keygen(
    std::uint8_t* public_key,
    std::uint8_t* secret_key,
    std::uint32_t* q,
    std::uint8_t* valid,
    char* error,
    std::size_t error_len
) {
    try {
        SHRINCS::PublicKey pk;
        SHRINCS::SecretKey sk;
        SHRINCS::State state;
        SHRINCS::shrincs_key_gen(pk, sk, state);
        export_pk(pk, public_key);
        export_sk(sk, secret_key);
        *q = state.q;
        *valid = state.valid ? 1 : 0;
        return 0;
    } catch (const std::exception& exception) {
        set_error(error, error_len, exception.what());
        return 1;
    } catch (...) {
        set_error(error, error_len, "unknown SHRINCS key generation error");
        return 1;
    }
}

extern "C" int ssw_shrincs_sign_stateful(
    const std::uint8_t* message,
    std::size_t message_len,
    const std::uint8_t* secret_key,
    std::uint32_t* q,
    std::uint8_t* valid,
    std::uint8_t* signature,
    std::size_t signature_capacity,
    std::size_t* signature_len,
    char* error,
    std::size_t error_len
) {
    try {
        SHRINCS::SecretKey sk;
        import_sk(secret_key, sk);
        SHRINCS::State state;
        state.q = *q;
        state.valid = *valid != 0;
        const std::vector<unsigned char> bytes(message, message + message_len);
        unsigned char* result = SHRINCS::shrincs_sign_stateful(bytes, sk, state);
        if (result == nullptr) {
            set_error(error, error_len, "SHRINCS stateful signing failed");
            return 1;
        }
        std::size_t path_height = state.q > FFI_HSF ? FFI_HSF : state.q;
        const std::size_t result_len =
            FFI_N + FFI_WOTS_SIGN_LEN + path_height * FFI_N;
        if (result_len > signature_capacity) {
            delete[] result;
            set_error(error, error_len, "SHRINCS signature output buffer is too small");
            return 1;
        }
        std::memcpy(signature, result, result_len);
        delete[] result;
        *q = state.q;
        *valid = state.valid ? 1 : 0;
        *signature_len = result_len;
        return 0;
    } catch (const std::exception& exception) {
        set_error(error, error_len, exception.what());
        return 1;
    } catch (...) {
        set_error(error, error_len, "unknown SHRINCS signing error");
        return 1;
    }
}

extern "C" int ssw_shrincs_sign_stateless(
    const std::uint8_t* message,
    std::size_t message_len,
    const std::uint8_t* secret_key,
    std::uint8_t* signature,
    std::size_t signature_capacity,
    std::size_t* signature_len,
    char* error,
    std::size_t error_len
) {
    try {
        if (signature_capacity < FFI_SL_SIZE) {
            set_error(error, error_len, "SHRINCS signature output buffer is too small");
            return 1;
        }
        SHRINCS::SecretKey sk;
        import_sk(secret_key, sk);
        const std::vector<unsigned char> bytes(message, message + message_len);
        unsigned char* result = SHRINCS::shrincs_sign_stateless(bytes, sk);
        if (result == nullptr) {
            set_error(error, error_len, "SHRINCS stateless signing failed");
            return 1;
        }
        std::memcpy(signature, result, FFI_SL_SIZE);
        delete[] result;
        *signature_len = FFI_SL_SIZE;
        return 0;
    } catch (const std::exception& exception) {
        set_error(error, error_len, exception.what());
        return 1;
    } catch (...) {
        set_error(error, error_len, "unknown SHRINCS signing error");
        return 1;
    }
}

extern "C" int ssw_shrincs_verify(
    const std::uint8_t* message,
    std::size_t message_len,
    const std::uint8_t* signature,
    std::size_t signature_len,
    const std::uint8_t* public_key,
    char* error,
    std::size_t error_len
) {
    const bool stateful_length =
        signature_len >= FFI_STATEFUL_MIN_SIZE &&
        signature_len <= FFI_STATEFUL_MAX_SIZE &&
        (signature_len - FFI_N - FFI_WOTS_SIGN_LEN) % FFI_N == 0;
    if (!stateful_length && signature_len != FFI_SL_SIZE) {
        return 2;
    }
    try {
        SHRINCS::PublicKey pk;
        import_pk(public_key, pk);
        const std::vector<unsigned char> bytes(message, message + message_len);
        return SHRINCS::shrincs_verify(bytes, signature, static_cast<std::uint32_t>(signature_len), pk) ? 0 : 2;
    } catch (const std::exception& exception) {
        set_error(error, error_len, exception.what());
        return 1;
    } catch (...) {
        set_error(error, error_len, "unknown SHRINCS verification error");
        return 1;
    }
}
