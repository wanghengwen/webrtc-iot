#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "utils.h"

void addr_set_family(Address* addr, int family) {
  switch (family) {
    case AF_INET6:
      addr->family = AF_INET6;
      break;
    case AF_INET:
    default:
      addr->family = AF_INET;
      break;
  }
}

void addr_set_port(Address* addr, uint16_t port) {
  addr->port = port;
  switch (addr->family) {
    case AF_INET6:
      addr->sin6.sin6_port = htons(port);
      break;
    case AF_INET:
    default:
      addr->sin.sin_port = htons(port);
      break;
  }
}

int addr_from_string(const char* buf, Address* addr) {
  if (inet_pton(AF_INET, buf, &(addr->sin.sin_addr)) == 1) {
    addr_set_family(addr, AF_INET);
    return 1;
  } else if (inet_pton(AF_INET6, buf, &(addr->sin6.sin6_addr)) == 1) {
    addr_set_family(addr, AF_INET6);
    return 1;
  }
  return 0;
}

int addr_to_string(const Address* addr, char* buf, size_t len) {
  // 添加空指针检查
  if (!addr || !buf || len == 0) {
    if (buf && len > 0) {
      strncpy(buf, "(null)", len - 1);
      buf[len - 1] = '\0';
    }
    return 0;
  }
  
  memset(buf, 0, len);  // 修复: sizeof(len) -> len
  switch (addr->family) {
    case AF_INET6:
      return inet_ntop(AF_INET6, &addr->sin6.sin6_addr, buf, len) != NULL;
    case AF_INET:
    default:
      return inet_ntop(AF_INET, &addr->sin.sin_addr, buf, len) != NULL;
  }
  return 0;
}

int addr_equal(const Address* a, const Address* b) {
  // 检查空指针
  if (!a || !b) {
    return (a == b) ? 1 : 0;  // 两个都为空返回真，否则返回假
  }
  
  // 首先比较地址族
  if (a->family != b->family) {
    return 0;
  }
  
  // 比较端口号
  if (a->port != b->port) {
    return 0;
  }
  
  // 根据地址族比较具体的地址
  switch (a->family) {
    case AF_INET:
      // 比较 IPv4 地址
      if (a->sin.sin_addr.s_addr != b->sin.sin_addr.s_addr) {
        return 0;
      }
      // 比较 IPv4 端口（冗余检查，但保证一致性）
      if (a->sin.sin_port != b->sin.sin_port) {
        return 0;
      }
      break;
      
    case AF_INET6:
      // 比较 IPv6 地址（128位，16字节）
      if (memcmp(&a->sin6.sin6_addr, &b->sin6.sin6_addr, sizeof(struct in6_addr)) != 0) {
        return 0;
      }
      // 比较 IPv6 端口
      if (a->sin6.sin6_port != b->sin6.sin6_port) {
        return 0;
      }
      // 比较 IPv6 scope ID（对于链路本地地址很重要）
      if (a->sin6.sin6_scope_id != b->sin6.sin6_scope_id) {
        return 0;
      }
      break;
      
    default:
      // 未知的地址族，认为不相等
      return 0;
  }
  
  // 所有字段都相等
  return 1;
}
