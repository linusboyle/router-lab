#ifndef LIB_CPP
#define LIB_CPP

#include "router_hal.h"
#include "rip.hpp"
#include "router.hpp"

void ip_get_addr(uint8_t *packet, in_addr_t *src_addr, in_addr_t *dst_addr);

bool ip_check_ttl(uint8_t *packet);

void write_length_16b(uint8_t *start, uint32_t len);

inline uint32_t to_netaddr_24b(uint32_t host_addr) {
    return host_addr & 0x00ffffff;
}

inline size_t ip_header_length(uint8_t *packet) { // in bytes
    uint8_t IHL = (*packet) & 0x0f; // in words (32bit)
    return static_cast<size_t> (IHL * 4);
}

inline uint16_t ip_get_checksum(uint8_t *packet) {
    uint16_t* hw = reinterpret_cast<uint16_t*>(packet + 10);
    uint16_t retval = *hw;
    return retval;
}

uint16_t ip_compute_checksum(uint8_t *packet, size_t hl);

bool ip_validate_checksum(uint8_t *packet);

void ip_update_checksum(uint8_t *packet);

bool ip_packet_forward(uint8_t *packet);

inline uint32_t ip_total_length(const uint8_t *packet) {
    uint8_t hbit = *(packet + 2);
    uint8_t lbit = *(packet + 3);
    uint32_t retval = static_cast<uint32_t>(hbit);
    // transform endian
    retval <<= 8;
    retval += static_cast<uint32_t>(lbit);
    return retval;
}

inline uint32_t rip_num_entry(uint32_t hl, uint32_t tl) {
    return (tl - hl - 8 - 4) / 20;
}

bool rip_disassemble(uint8_t *packet, uint32_t len, RipPacket *output);

uint32_t rip_assemble(RipPacket *rip, uint8_t *buffer);

uint32_t gen_mask(uint32_t len);

void update(bool isInsert, RoutingTableEntry entry);

bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
#endif /* ifndef LIB_CPP */
