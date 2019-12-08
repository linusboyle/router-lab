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

static bool validateIPChecksum(uint8_t *packet, size_t) {
    size_t hl = header_length(packet);
    uint16_t old_sum = get_in_checksum(packet);
    uint16_t new_sum = compute_new_checksum(packet, hl);
    return old_sum == new_sum;
}

static void updateTTL(uint8_t *packet) {
    uint8_t *targ = packet + 8;
    uint8_t ttl = *targ;
    *targ = ttl - 1u;
}

void updateChksm(uint8_t *packet) {
    size_t hl = header_length(packet);
    uint16_t* hw = reinterpret_cast<uint16_t*>(packet + 10);
    *hw = 0;
    uint16_t new_sum = compute_new_checksum(packet, hl);
    *hw = new_sum;
}

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
    if (!validateIPChecksum(packet, len))
        return false;
    updateTTL(packet);
    updateChksm(packet);
    return true;
}
