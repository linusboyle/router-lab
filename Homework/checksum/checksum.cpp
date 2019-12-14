#include <stdint.h>
#include <stdlib.h>

static inline size_t header_length(uint8_t *packet) { // in bytes
    uint8_t IHL = (*packet) & 0x0f; // in words (32bit)
    return static_cast<size_t> (IHL * 4);
}

static inline uint16_t get_in_checksum(uint8_t *packet) {
    uint16_t* hw = reinterpret_cast<uint16_t*>(packet + 10);
    uint16_t retval = *hw;
    *hw = 0x0000;
    return retval;
}

static uint16_t compute_new_checksum(uint8_t *packet, size_t hl) {
    uint8_t* end = packet + hl;

    uint32_t checkSum = 0x00000000;
    while (packet != end) {
        checkSum += *reinterpret_cast<uint16_t*>(packet);
        packet += 2;
    }
    checkSum = (checkSum >> 16) + (checkSum & 0x0000ffff);
    checkSum += (checkSum >> 16);

    uint16_t csm = static_cast<uint16_t> (~checkSum);
    return csm;
}

/**
 * @brief 进行 IP头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t ) {
    size_t hl = header_length(packet);
    uint16_t old_sum = get_in_checksum(packet);
    uint16_t new_sum = compute_new_checksum(packet, hl);
    return old_sum == new_sum;
}
