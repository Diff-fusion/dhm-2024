#include "chall_decrypt.h"

uint8_t shift_lfsr8(uint64_t* lfsr) {
    uint8_t ret = *lfsr >> (64-8);
    for (int i = 0; i < 8; i++) {
        int feedback = *lfsr >> 63;
        *lfsr <<= 1;
        if (feedback) {
            *lfsr ^= 0x1b;
        }
    }
    return ret;
}

esp_err_t decrypt_extended(char* key, char* iv, char* data, int len) {
    uint64_t lfsr = *(uint64_t*)key;
    for (int i = 0; i < 8; i++) {
        shift_lfsr8(&lfsr);
    }
    lfsr ^= *(uint64_t*)iv;
    for (int i = 0; i < 8; i++) {
        shift_lfsr8(&lfsr);
    }

    for (int i = 0; i < len; i++) {
        uint8_t byte = shift_lfsr8(&lfsr);
        data[i] ^= byte;
    }
    return ESP_OK;
}
