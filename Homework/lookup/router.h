#include <stdint.h>
#include <list>
typedef struct {
    uint32_t addr;
    uint32_t len;
    uint32_t if_index;
    uint32_t nexthop;
    uint32_t metric;
    uint64_t update_timer;
    bool expire;
    uint64_t gc_timer;
} RoutingTableEntry;
using RoutingTable = std::list<RoutingTableEntry>;
