#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "socket.h"
#include "utils.h"
#include "network_config.h"



int udp_socket_add_multicast_group(UdpSocket* udp_socket, Address* mcast_addr) {
  int ret = 0;
  struct ip_mreq imreq = {0};
  struct in_addr iaddr = {0};

  imreq.imr_interface.s_addr = INADDR_ANY;
  // IPV4 only
  imreq.imr_multiaddr.s_addr = mcast_addr->sin.sin_addr.s_addr;

  if ((ret = setsockopt(udp_socket->fd, IPPROTO_IP, IP_MULTICAST_IF, &iaddr, sizeof(struct in_addr))) < 0) {
    LOGE("Failed to set IP_MULTICAST_IF: %d", ret);
    return ret;
  }

  if ((ret = setsockopt(udp_socket->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &imreq, sizeof(struct ip_mreq))) < 0) {
    LOGE("Failed to set IP_ADD_MEMBERSHIP: %d", ret);
    return ret;
  }

  return 0;
}

int udp_socket_open(UdpSocket* udp_socket, int family, int port) {
  int ret;
  int reuse = 1;
  struct sockaddr* sa;
  socklen_t sock_len;

  udp_socket->bind_addr.family = family;
  switch (family) {
    case AF_INET6:
      udp_socket->fd = socket(AF_INET6, SOCK_DGRAM, 0);
      udp_socket->bind_addr.sin6.sin6_family = AF_INET6;
      udp_socket->bind_addr.sin6.sin6_port = htons(port);
      udp_socket->bind_addr.sin6.sin6_addr = in6addr_any;
      udp_socket->bind_addr.port = ntohs(udp_socket->bind_addr.sin6.sin6_port);
      sa = (struct sockaddr*)&udp_socket->bind_addr.sin6;
      sock_len = sizeof(struct sockaddr_in6);
      break;
    case AF_INET:
    default:
      udp_socket->fd = socket(AF_INET, SOCK_DGRAM, 0);
      udp_socket->bind_addr.sin.sin_family = AF_INET;
      udp_socket->bind_addr.sin.sin_port = htons(port);
      udp_socket->bind_addr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
      sa = (struct sockaddr*)&udp_socket->bind_addr.sin;
      sock_len = sizeof(struct sockaddr_in);
      break;
  }

  if (udp_socket->fd < 0) {
    LOGE("Failed to create socket");
    return -1;
  }

  do {
    // SO_REUSEADDR 在某些平台可能不支持，改用 SO_REUSEPORT
#ifdef SO_REUSEPORT
    if ((ret = setsockopt(udp_socket->fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse))) < 0) {
      LOGW("SO_REUSEPORT failed: %s", strerror(errno));
    }
#else
    if ((ret = setsockopt(udp_socket->fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) < 0) {
      LOGW("SO_REUSEADDR failed: %s", strerror(errno));
    }
#endif

    // 增加UDP发送和接收缓冲区大小以防止"Not enough space"错误
    // ESP32 平台可能对缓冲区大小有限制，尝试不同的值
    int send_buf_sizes[] = {16384, 8192, 4096};  // 尝试 16KB, 8KB, 4KB
    int recv_buf_sizes[] = {16384, 8192, 4096};
    int send_buf_size = 0, recv_buf_size = 0;
    
    // 尝试设置发送缓冲区
    for (int i = 0; i < sizeof(send_buf_sizes)/sizeof(send_buf_sizes[0]); i++) {
      if (setsockopt(udp_socket->fd, SOL_SOCKET, SO_SNDBUF, 
                     &send_buf_sizes[i], sizeof(send_buf_sizes[i])) == 0) {
        send_buf_size = send_buf_sizes[i];
        LOGI("UDP send buffer size set to %d bytes", send_buf_size);
        break;
      }
    }
    
    if (send_buf_size == 0) {
      LOGW("Failed to set any send buffer size, using system default");
    }
    
    // 尝试设置接收缓冲区
    for (int i = 0; i < sizeof(recv_buf_sizes)/sizeof(recv_buf_sizes[0]); i++) {
      if (setsockopt(udp_socket->fd, SOL_SOCKET, SO_RCVBUF, 
                     &recv_buf_sizes[i], sizeof(recv_buf_sizes[i])) == 0) {
        recv_buf_size = recv_buf_sizes[i];
        LOGI("UDP receive buffer size set to %d bytes", recv_buf_size);
        break;
      }
    }
    
    if (recv_buf_size == 0) {
      LOGW("Failed to set any receive buffer size, using system default");
    }
    
    // 获取实际设置的缓冲区大小
    socklen_t optlen = sizeof(send_buf_size);
    if (getsockopt(udp_socket->fd, SOL_SOCKET, SO_SNDBUF, &send_buf_size, &optlen) == 0) {
      LOGI("Actual send buffer size: %d bytes", send_buf_size);
    }
    optlen = sizeof(recv_buf_size);
    if (getsockopt(udp_socket->fd, SOL_SOCKET, SO_RCVBUF, &recv_buf_size, &optlen) == 0) {
      LOGI("Actual receive buffer size: %d bytes", recv_buf_size);
    }

    if ((ret = bind(udp_socket->fd, sa, sock_len)) < 0) {
      LOGE("Failed to bind socket: %d", ret);
      break;
    }

    if (getsockname(udp_socket->fd, sa, &sock_len) < 0) {
      LOGE("Get socket info failed");
      break;
    }
  } while (0);

  if (ret < 0) {
    udp_socket_close(udp_socket);
    return -1;
  }

  switch (udp_socket->bind_addr.family) {
    case AF_INET6:
      udp_socket->bind_addr.port = ntohs(udp_socket->bind_addr.sin6.sin6_port);
      break;
    case AF_INET:
    default:
      udp_socket->bind_addr.port = ntohs(udp_socket->bind_addr.sin.sin_port);
      break;
  }

  return 0;
}

void udp_socket_close(UdpSocket* udp_socket) {
  if (udp_socket->fd > 0) {
    close(udp_socket->fd);
  }
}

int udp_socket_sendto(UdpSocket* udp_socket, Address* addr, const uint8_t* buf, int len) {
  struct sockaddr* sa;
  socklen_t sock_len;
  int ret = -1;

  if (udp_socket->fd < 0) {
    LOGE("sendto before socket init");
    return -1;
  }

  switch (addr->family) {
    case AF_INET6:
      addr->sin6.sin6_family = AF_INET6;
      sa = (struct sockaddr*)&addr->sin6;
      sock_len = sizeof(struct sockaddr_in6);
      break;
    case AF_INET:
    default:
      addr->sin.sin_family = AF_INET;
      sa = (struct sockaddr*)&addr->sin;
      sock_len = sizeof(struct sockaddr_in);
      break;
  }

  if ((ret = sendto(udp_socket->fd, buf, len, 0, sa, sock_len)) < 0) {
    LOGE("Failed to sendto: %s (errno=%d)", strerror(errno), errno);
    return -1;
  }
  
  return ret;
}


int udp_socket_recvfrom(UdpSocket* udp_socket, Address* addr, uint8_t* buf, int len) {
  struct sockaddr_in6 sin6;
  struct sockaddr_in sin;
  struct sockaddr* sa;
  socklen_t sock_len;
  int ret;

  if (udp_socket->fd < 0) {
    LOGE("recvfrom before socket init");
    return -1;
  }

  switch (udp_socket->bind_addr.family) {
    case AF_INET6:
      sin6.sin6_family = AF_INET6;
      sa = (struct sockaddr*)&sin6;
      sock_len = sizeof(struct sockaddr_in6);
      break;
    case AF_INET:
    default:
      sin.sin_family = AF_INET;
      sa = (struct sockaddr*)&sin;
      sock_len = sizeof(struct sockaddr_in);
      break;
  }

  if ((ret = recvfrom(udp_socket->fd, buf, len, 0, sa, &sock_len)) < 0) {
    LOGE("Failed to recvfrom: %s", strerror(errno));
    return -1;
  }

  if (addr) {
    switch (udp_socket->bind_addr.family) {
      case AF_INET6:
        addr->family = AF_INET6;
        addr->port = htons(sin6.sin6_port);
        memcpy(&addr->sin6, &sin6, sizeof(struct sockaddr_in6));
        break;
      case AF_INET:
      default:
        addr->family = AF_INET;
        addr->port = htons(sin.sin_port);
        memcpy(&addr->sin, &sin, sizeof(struct sockaddr_in));
        break;
    }
  }

  return ret;
}

int tcp_socket_open(TcpSocket* tcp_socket, int family) {
  tcp_socket->bind_addr.family = family;
  switch (family) {
    case AF_INET6:
      tcp_socket->fd = socket(AF_INET6, SOCK_STREAM, 0);
      break;
    case AF_INET:
    default:
      tcp_socket->fd = socket(AF_INET, SOCK_STREAM, 0);
      break;
  }

  if (tcp_socket->fd < 0) {
    LOGE("Failed to create socket");
    return -1;
  }
  return 0;
}

int tcp_socket_connect(TcpSocket* tcp_socket, Address* addr) {
  char addr_string[ADDRSTRLEN];
  int ret;
  struct sockaddr* sa;
  socklen_t sock_len;

  if (tcp_socket->fd < 0) {
    LOGE("Connect before socket init");
    return -1;
  }

  switch (addr->family) {
    case AF_INET6:
      addr->sin6.sin6_family = AF_INET6;
      sa = (struct sockaddr*)&addr->sin6;
      sock_len = sizeof(struct sockaddr_in6);
      break;
    case AF_INET:
    default:
      addr->sin.sin_family = AF_INET;
      sa = (struct sockaddr*)&addr->sin;
      sock_len = sizeof(struct sockaddr_in);
      break;
  }

  addr_to_string(addr, addr_string, sizeof(addr_string));
  LOGI("Connecting to server: %s:%d", addr_string, addr->port);
  if ((ret = connect(tcp_socket->fd, sa, sock_len)) < 0) {
    LOGE("Failed to connect to server");
    return -1;
  }

  LOGI("Server is connected");
  return 0;
}

void tcp_socket_close(TcpSocket* tcp_socket) {
  if (tcp_socket->fd > 0) {
    close(tcp_socket->fd);
  }
}

int tcp_socket_send(TcpSocket* tcp_socket, const uint8_t* buf, int len) {
  int ret;

  if (tcp_socket->fd < 0) {
    LOGE("sendto before socket init");
    return -1;
  }

  ret = send(tcp_socket->fd, buf, len, 0);
  if (ret < 0) {
    LOGE("Failed to send: %s", strerror(errno));
    return -1;
  }
  return ret;
}

int tcp_socket_recv(TcpSocket* tcp_socket, uint8_t* buf, int len) {
  int ret;

  if (tcp_socket->fd < 0) {
    LOGE("recvfrom before socket init");
    return -1;
  }

  ret = recv(tcp_socket->fd, buf, len, 0);
  if (ret < 0) {
    LOGE("Failed to recv: %s", strerror(errno));
    return -1;
  }
  return ret;
}
