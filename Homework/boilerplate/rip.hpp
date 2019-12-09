#ifndef RIP_HPP
#define RIP_HPP

#include <cstdint>
#define RIP_MAX_ENTRY 25
struct RipEntry {
  // all fields are big endian
  // we don't store 'family', as it is always 2(response) and 0(request)
  // we don't store 'tag', as it is always 0
public:
  uint32_t addr;
  uint32_t mask;
  uint32_t nexthop;
  uint32_t metric;
};

struct RipPacket {
  uint32_t numEntries;
  // all fields below are big endian
  uint8_t command;
  // we don't store 'version', as it is always 2
  // we don't store 'zero', as it is always 0
  RipEntry entries[RIP_MAX_ENTRY];
};
#endif
