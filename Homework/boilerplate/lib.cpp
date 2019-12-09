#include "lib.hpp"

union helper {
    uint32_t b32;
    uint16_t b16[2];
    uint8_t b8[4];
};

void ip_get_addr(uint8_t *packet, in_addr_t *src_addr, in_addr_t *dst_addr) {
    uint32_t *ptr = reinterpret_cast<uint32_t *>(packet);
    *src_addr = static_cast<in_addr_t>(*(ptr + 3));
    *dst_addr = static_cast<in_addr_t>(*(ptr + 4));
}

bool ip_check_ttl(uint8_t *packet) {
    uint8_t *targ = packet + 8;
    uint8_t ttl = *targ;
    return (ttl > 0);
}

void write_length_16b(uint8_t *start, uint32_t len) {
    union helper h;
    h.b32 = len;
    *start = h.b8[1];
    *(start + 1) = h.b8[0];
}

