#ifndef MDNS_H_
#define MDNS_H_

#include <stdlib.h>
#include "address.h"

#ifdef __cplusplus
extern "C" {
#endif

int mdns_resolve_addr(const char* hostname, Address* addr);

#ifdef __cplusplus
}
#endif

#endif  // MDNS_H_
