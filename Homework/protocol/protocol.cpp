#include "rip.h"
#include <stdint.h>
#include <stdlib.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

inline uint32_t ip_header_length(const uint8_t *packet) { // in bytes
    uint8_t IHL = (*packet) & 0x0f; // in words (32bit)
    return static_cast<uint32_t> (IHL * 4);
}

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

union helper {
    uint32_t word;
    uint8_t bytes[4];
};

bool check_mask(uint32_t mask) {
    // transform
    union helper h1;
    h1.word = mask;
    union helper h2;
    h2.bytes[0] = h1.bytes[3];
    h2.bytes[1] = h1.bytes[2];
    h2.bytes[2] = h1.bytes[1];
    h2.bytes[3] = h1.bytes[0];
    uint32_t lm = ~h2.word;

    return (lm & (lm + 1)) == 0;
}

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
    uint32_t hl = ip_header_length(packet);
    uint32_t tl = ip_total_length(packet);
    if (tl > len) return false;

    const uint8_t *rip = packet + hl + 8; // 8 : udp header
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

        re.addr = *reinterpret_cast<const uint32_t*>(rip); rip += 4;
        re.mask = *reinterpret_cast<const uint32_t*>(rip); rip += 4;
        re.nexthop = *reinterpret_cast<const uint32_t*>(rip); rip += 4;
        re.metric = *reinterpret_cast<const uint32_t*>(rip); rip += 4;

        if (!check_mask(re.mask)) return false;

        {
            union helper h;
            h.word = re.metric;
            if (h.bytes[0] != 0 || h.bytes[1] != 0 || h.bytes[2] != 0) return false;
            if (h.bytes[3] == 0 || h.bytes[3] > 16) return false;
        }

        output->entries[iter++] = re;
    }

    return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
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
        *reinterpret_cast<uint32_t*>(buffer) = re.metric; buffer += 4;
    }

    return (4 + 20 * rip -> numEntries);
}
