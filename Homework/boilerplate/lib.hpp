#ifndef LIB_CPP
#define LIB_CPP

#include "router_hal.h"

void ip_get_addr(uint8_t *packet, in_addr_t *src_addr, in_addr_t *dst_addr);

bool ip_check_ttl(uint8_t *packet);

void write_length_16b(uint8_t *start, uint32_t len);

inline uint32_t to_netaddr_24b(uint32_t host_addr) {
    return host_addr & 0x00ffffff;
}

#endif /* ifndef LIB_CPP */
