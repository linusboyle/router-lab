#include "lib.hpp"
#include <limits>
#include <algorithm>

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

uint16_t ip_compute_checksum(uint8_t *packet, size_t hl) {
    uint16_t* hw = reinterpret_cast<uint16_t*>(packet + 10);
    uint16_t tmp = *hw;
    *hw = 0;
    uint8_t* end = packet + hl;

    uint32_t checkSum = 0x00000000;
    while (packet != end) {
        checkSum += *reinterpret_cast<uint16_t*>(packet);
        packet += 2;
    }
    checkSum = (checkSum >> 16) + (checkSum & 0x0000ffff);
    checkSum += (checkSum >> 16);

    uint16_t csm = static_cast<uint16_t> (~checkSum);
    *hw = tmp;
    return csm;
}

bool ip_validate_checksum(uint8_t *packet) {
    size_t hl = ip_header_length(packet);
    uint16_t old_sum = ip_get_checksum(packet);
    uint16_t new_sum = ip_compute_checksum(packet, hl);
    return old_sum == new_sum;
}

void ip_update_ttl(uint8_t *packet) {
    uint8_t *targ = packet + 8;
    uint8_t ttl = *targ;
    *targ = ttl - 1u;
}

void ip_update_checksum(uint8_t *packet) {
    size_t hl = ip_header_length(packet);
    uint16_t* hw = reinterpret_cast<uint16_t*>(packet + 10);
    uint16_t new_sum = ip_compute_checksum(packet, hl);
    *hw = new_sum;
}

bool ip_packet_forward(uint8_t *packet) {
    if (!ip_validate_checksum(packet))
        return false;
    ip_update_ttl(packet);
    ip_update_checksum(packet);
    return true;
}

uint32_t change_endian_32b(uint32_t word) {
    union helper h1;
    h1.b32 = word;
    union helper h2;
    h2.b8[0] = h1.b8[3];
    h2.b8[1] = h1.b8[2];
    h2.b8[2] = h1.b8[1];
    h2.b8[3] = h1.b8[0];
    return h2.b32;
}

bool check_subnet_mask(uint32_t mask) {
    // transform
    uint32_t tl = change_endian_32b(mask);
    uint32_t lm = ~tl;

    return (lm & (lm + 1)) == 0;
}

bool rip_disassemble(uint8_t *packet, uint32_t len, RipPacket *output) {
    uint32_t hl = ip_header_length(packet);
    uint32_t tl = ip_total_length(packet);
    if (tl > len) return false;

    uint8_t *rip = packet + hl + 8; // 8 : udp header
    uint32_t num_entry = rip_num_entry(hl, len);

    uint8_t command = *(rip++);
    uint8_t version = *(rip++);
    uint8_t zeroH = *(rip++);
    uint8_t zeroL = *(rip++);
    if (command != 1 && command != 2) return false;
    if (version != 2) return false;
    if (zeroH != 0 || zeroL != 0) return false;

    output->numEntries = num_entry;
    output->command = command;

    uint32_t iter = 0;
    while (iter != num_entry) {
        RipEntry re;
        uint8_t familyH = *(rip++);
        uint8_t familyL = *(rip++);
        if (familyH != 0) return false;
        if ((command == 1 && familyL != 0) || (command == 2 && familyL != 2)) return false;

        uint8_t tagH = *(rip++);
        uint8_t tagL = *(rip++);
        if (tagH != 0 || tagL != 0) return false;

        re.addr = *reinterpret_cast<uint32_t*>(rip); rip += 4;
        re.mask = *reinterpret_cast<uint32_t*>(rip); rip += 4;
        re.nexthop = *reinterpret_cast<uint32_t*>(rip); rip += 4;
        re.metric = change_endian_32b(*reinterpret_cast<uint32_t*>(rip)); rip += 4;

        if (!check_subnet_mask(re.mask)) return false;
        if (re.metric == 0 || re.metric > 16) return false;

        output->entries[iter++] = re;
    }

    return true;
}

uint32_t rip_assemble(RipPacket *rip, uint8_t *buffer) {
    *(buffer++) = rip->command;
    *(buffer++) = 2; // version
    *(buffer++) = 0; // zeros
    *(buffer++) = 0;

    uint32_t iter = 0;
    while (iter != rip -> numEntries) {
        auto re = rip->entries[iter++];
        // family
        *(buffer++) = 0;
        if (rip -> command == 2)
            *(buffer++) = 2;
        else
            *(buffer++) = 0;
        // tag
        *(buffer++) = 0;
        *(buffer++) = 0;
        // addr
        *reinterpret_cast<uint32_t*>(buffer) = re.addr; buffer += 4;
        *reinterpret_cast<uint32_t*>(buffer) = re.mask; buffer += 4;
        *reinterpret_cast<uint32_t*>(buffer) = re.nexthop; buffer += 4;
        *reinterpret_cast<uint32_t*>(buffer) = change_endian_32b(re.metric); buffer += 4;
    }

    return (4 + 20 * rip -> numEntries);
}

uint32_t gen_mask(uint32_t len) {
    if (len == 0) return 0; // cope with C/C++ Undefined Behaviour
     
    return std::numeric_limits<uint32_t>::max() >> (32 - len); 
}

RoutingTable rt;

void insert(RoutingTableEntry& entry) {
    auto itr = std::find_if(rt.begin(), rt.end(), [&entry](const RoutingTableEntry& e) {
                return (e.addr == entry.addr) &&
                       (e.len == entry.len);
            });
    if (itr != rt.end())
        *itr = entry;
    else
        rt.push_front(entry);
}

void remove(RoutingTableEntry& entry) {
    rt.remove_if([&entry](const RoutingTableEntry& e) {
                return (e.addr == entry.addr) &&
                       (e.len == entry.len);
            });
}

void update(bool isInsert, RoutingTableEntry entry) {
    if (isInsert) {
        insert(entry);
    } else {
        remove(entry);
    }
}

bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
    uint32_t len = 0;
    bool found = false;

    for (const RoutingTableEntry& e : rt) {
        if (e.len >= len && !e.expire && e.metric < 16) {
            uint32_t mask = gen_mask(e.len);
            if ((addr & mask) == (e.addr & mask)) {
                *nexthop = e.nexthop;
                *if_index = e.if_index;
                len = e.len;
                found = true;
            }
        }
    }

    return found;
}
