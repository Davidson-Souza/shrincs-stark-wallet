#include <openssl/sha.h>
#include <stddef.h>
#include <stdint.h>

#define FIELD_MODULUS UINT64_C(3221225473)

void field_powers(uint64_t *out, size_t len, uint64_t start, uint64_t step) {
    uint64_t value = start;
    for (size_t i = 0; i < len; ++i) {
        out[i] = value;
        value = (uint64_t)((__uint128_t)value * step % FIELD_MODULUS);
    }
}

void hash_field_rows(const uint64_t *rows, size_t row_count, size_t columns, unsigned char *out) {
    unsigned char encoded[256];
    for (size_t row = 0; row < row_count; ++row) {
        for (size_t column = 0; column < columns; ++column) {
            uint32_t value = (uint32_t)rows[row * columns + column];
            encoded[4 * column] = (unsigned char)(value >> 24);
            encoded[4 * column + 1] = (unsigned char)(value >> 16);
            encoded[4 * column + 2] = (unsigned char)(value >> 8);
            encoded[4 * column + 3] = (unsigned char)value;
        }
        SHA256(encoded, 4 * columns, out + 32 * row);
    }
}

void hash_merkle_parents(const unsigned char *children, size_t parent_count, unsigned char *out) {
    for (size_t i = 0; i < parent_count; ++i) {
        SHA256(children + 64 * i, 64, out + 32 * i);
    }
}
