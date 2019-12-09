#include "lib.hpp"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>

constexpr in_addr_t RIP_MULTICAST_ADDR = 0x090000e0;
constexpr uint32_t RIP_UNSOLICITED_INTERVAL = 30000;
constexpr uint32_t RIP_TIMEOUT_INTERVAL = 180000;
constexpr uint32_t RIP_EXPIRE_INTERVAL = 120000;

#define ENABLE_RIP_DEBUG

uint32_t count1(uint32_t n) {
    uint32_t retval = 0;

    while (n) {
        retval++;
        n &= (n - 1);
    }

    return retval;
}

extern RoutingTable rt;

uint32_t generate_packet_p1(uint8_t *p, uint32_t target_addr, uint32_t if_index) {
    RipPacket resp;

    uint32_t iter = 0;
    for (const RoutingTableEntry &e : rt) { 
        RipEntry re;
        re.addr = e.addr;
        re.mask = gen_mask(e.len);
        re.nexthop = 0; // 0.0.0.0 stands for the originator
        if (e.nexthop == 0 && e.if_index == if_index) {
            // direct route
            re.metric = e.metric;
        } else if (target_addr == RIP_MULTICAST_ADDR && if_index == e.if_index) {
            re.metric = 16;
        } else if (e.nexthop == target_addr) {
            // split horizon with reverse poisoning
            re.metric = 16;
        } else {
            re.metric = e.metric;
        }
        resp.entries[iter++] = re;
        if (iter == RIP_MAX_ENTRY) break; // TODO: there should be a better solution...
    }
    resp.numEntries = iter;
    resp.command = 2;

    // IP
    p[0] = 0x45; // version + ihl
    p[1] = 0x0; // tos
    p[4] = 0x0; // id
    p[5] = 0x0;
    p[6] = 0x0; // flag
    p[7] = 0x0;
    p[8] = 0x1; // ttl
    p[9] = 0x11; // protocal (udp)
    // UDP
    p[20] = 0x02; // src port 520
    p[21] = 0x08;
    p[22] = 0x02; // dst port 520
    p[23] = 0x08;
    p[26] = 0x0; // udp checksum, disabled
    p[27] = 0x0;
    // RIP
    uint32_t rip_len = rip_assemble(&resp, &p[20 + 8]);
    write_length_16b(&p[2], rip_len + 20 + 8); // ip - total length
    write_length_16b(&p[24], rip_len + 8); // udp - length
    ip_update_checksum(p); // checksum calculation for ip

    return rip_len + 20 + 8;
}

inline void generate_packet_p2(uint8_t *p, uint32_t myaddr, uint32_t dst_addr) {
    *reinterpret_cast<in_addr_t *>(p + 12) = myaddr; // 12 - 15
    *reinterpret_cast<in_addr_t *>(p + 16) = dst_addr; // 16 - 19
    ip_update_checksum(p);
}

uint32_t generate_packet_full(uint8_t *p, uint32_t myaddr, uint32_t dst_addr, uint32_t if_index) {
    uint32_t pl = generate_packet_p1(p, dst_addr, if_index);
    generate_packet_p2(p, myaddr, dst_addr);
    return pl;
}

inline uint32_t incr_metric(uint32_t metric) {
    uint32_t nM = metric + 1;
    return nM <= 16 ? nM : 16;
}

void update_from_rip(RipPacket *p, uint32_t if_index, uint32_t src_addr) {
    uint32_t num = p->numEntries;

    uint64_t time = HAL_GetTicks();
    for (uint32_t i = 0; i < num; ++i) {
        RipEntry re = p->entries[i];

        uint32_t next_addr = re.nexthop == 0 ? src_addr : re.nexthop; // rip-2 extension

        uint32_t new_metric = incr_metric(re.metric);
        RoutingTableEntry e = {
            .addr = re.addr,
            .len = count1(re.mask), // 'len' is the length of prefix 1
            .if_index = if_index,
            .nexthop = next_addr,
            .metric = new_metric,
            .update_timer = time,
            .expire = false,
            .gc_timer = 0
        };

        auto iter = std::find_if(rt.begin(), rt.end(), [&re](const RoutingTableEntry &e) {
            return (e.addr == re.addr && re.mask == gen_mask(e.len));
        });

        if (iter == rt.end()) {
            // not found, add it if accessible
            if (new_metric < 16) {
                update(true, e);
            }
        } else {
            if (src_addr == iter->nexthop) {
                // if packet comes from the best route,
                // update without checking metric is smaller
                if (new_metric == 16) {
                    update(false, e);
                } else {
                    update(true, e);
                }
            } else {
                uint32_t old_metric = iter->metric;
                if (new_metric < old_metric) {
                    update(true, e);
                }
            }
        }
    }
}

void update_rt_timer() {
    auto iter = rt.begin();
    uint64_t time = HAL_GetTicks();
    while (iter != rt.end()) {
        auto next = std::next(iter);

        if (iter -> expire) {
            if (time > iter->gc_timer + RIP_EXPIRE_INTERVAL) {
#ifdef ENABLE_RIP_DEBUG
                printf("An entry has been gc\n");
#endif
                rt.erase(iter);
            }
        } else {
            if (time > iter->update_timer + RIP_TIMEOUT_INTERVAL 
                    && iter->nexthop != 0) { // do not delete direct route
                iter->expire = true;
                iter->gc_timer = time;
                iter->metric = 16;
#ifdef ENABLE_RIP_DEBUG
                printf("An entry has expired\n");
#endif
            }
        }
        iter = next;
    }
}

int main(int, char**) {
    uint8_t packet[2048];
    uint8_t output[2048];

    // if 0: 10.0.0.1
    // if 1: 10.0.1.1
    // if 2: 10.42.0.1
    // if 3: 10.0.3.1
    in_addr_t addrs[N_IFACE_ON_BOARD] = { 0x0100000a, 0x0101000a, 0x01002a0a, 0x0103000a };

    // 0a.
    int res = HAL_Init(1, addrs);
    if (res < 0) {
	    return res;
    }

    uint64_t last_time = HAL_GetTicks();
    // 0b. Add direct routes
    for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
        RoutingTableEntry entry = {
            .addr = to_netaddr_24b(addrs[i]), // big endian
            .len = 24,        // small endian
            .if_index = i,    // small endian
            .nexthop = 0,      // big endian, means direct
            .metric = 1u,
            .update_timer = last_time,
            .expire = false,
            .gc_timer = 0
        };
        update(true, entry);
    }

    while (1) {
        update_rt_timer();

        uint64_t time = HAL_GetTicks();
        if (time > last_time + RIP_UNSOLICITED_INTERVAL) {
            // Unsolicited response; ref. RFC2453 3.8
            // send complete routing table to every interface
            for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
#ifdef ENABLE_RIP_DEBUG
                printf("Send Unsolicited response to if %d\n", i);
#endif
                uint32_t pl = generate_packet_full(output, addrs[i], RIP_MULTICAST_ADDR, i);
                macaddr_t dst_rt_mac;

                if (!HAL_ArpGetMacAddress(i, RIP_MULTICAST_ADDR, dst_rt_mac)) {
                    int ret = HAL_SendIPPacket(i, output, pl, dst_rt_mac);
#ifdef ENABLE_RIP_DEBUG
                    if (ret) {
                        printf("Send ip failed on if %d\n", i);
                    }
#endif
                } 
#ifdef ENABLE_RIP_DEBUG
                else {
                        printf("Arp failed\n");
                }
#endif
            }

            printf("30s Timer\n");
            last_time = time;
        }

        int mask = (1 << N_IFACE_ON_BOARD) - 1;
        macaddr_t src_mac;
        macaddr_t dst_mac;
        int if_index;
        res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac, 1000, &if_index);

        if (res == HAL_ERR_EOF) {
            break;
        } else if (res < 0) { // error
            return res;
        } else if (res == 0) { // Timeout
            continue;
        } else if (res > sizeof(packet)) {
            // packet is truncated, ignore it
            continue;
        }

        // 1. validate
        if (!ip_validate_checksum(packet)) {
            printf("Invalid IP Checksum\n");
            continue;
        }

        in_addr_t src_addr, dst_addr;
        ip_get_addr(packet, &src_addr, &dst_addr);
#ifdef ENABLE_RIP_DEBUG
        printf("receive packet from src:%x to dst:%x\n", src_addr, dst_addr);
#endif

        if (dst_addr == RIP_MULTICAST_ADDR) {
            RipPacket rip;
            if (rip_disassemble(packet, res, &rip)) {
                if (rip.command == 2) {
#ifdef ENABLE_RIP_DEBUG
                    printf("Receive a response from multicast addr\n");
#endif
                    update_from_rip(&rip, if_index, src_addr);
                } else {
#ifdef ENABLE_RIP_DEBUG
                    printf("Receive a request from multicast addr\n");
#endif
                    uint32_t pl = generate_packet_full(output, addrs[if_index], src_addr, if_index);
                    HAL_SendIPPacket(if_index, output, pl, src_mac);
                }
            } else {
#ifdef ENABLE_RIP_DEBUG
                    printf("Disassemble failed\n");
#endif
            }
            continue;
        }

        // 2. check whether dst is me
        bool dst_is_me = false;
        for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
            if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
                dst_is_me = true;
                break;
            }
        }

        if (dst_is_me) {
            // 3a.1
            RipPacket rip;
            // check and validate
            if (rip_disassemble(packet, res, &rip)) {
                if (rip.command == 1) {
#ifdef ENABLE_RIP_DEBUG
                    printf("Receive a request sent to me\n");
#endif
                    // 3a.3 request, ref. RFC2453 3.9.1
                    // only need to respond to whole table requests in the lab
                    uint32_t pl = generate_packet_full(output, dst_addr, src_addr, if_index);
                    // send it back
                    HAL_SendIPPacket(if_index, output, pl, src_mac);
                } else {
                    // 3a.2 response, ref. RFC2453 3.9.2
                    // update routing table , metric, if_index, nexthop
                    // TODO : triggered updates? ref. RFC2453 3.10.1
#ifdef ENABLE_RIP_DEBUG
                    printf("Receive a response sent to me\n");
#endif
                    update_from_rip(&rip, if_index, src_addr);
                }
            }
        } else {
            // 3b.1 dst is not me
            // forward
            // beware of endianness
            uint32_t nexthop, dest_if;
            if (query(dst_addr, &nexthop, &dest_if)) {
                // found
                macaddr_t dest_mac;
                // direct routing
                if (nexthop == 0) {
                    nexthop = dst_addr;
                }
                if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
                    // found
                    memcpy(output, packet, res);
                    // update ttl and checksum
                    ip_packet_forward(output);
                    if (ip_check_ttl(output)) HAL_SendIPPacket(dest_if, output, res, dest_mac);
                } else {
                    // mac not found, drop it
                    printf("ARP not found for %x\n", nexthop);
                }
            } else {
                // routing not found
                // *optionally*: send ICMP Host Unreachable
                printf("IP not found for %x\n", src_addr);
            }
        }
    }
    return 0;
}
