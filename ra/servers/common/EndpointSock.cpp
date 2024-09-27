#include <sys/types.h>
#include <sys/socket.h>


#include "EndpointSock.hpp"

int EndpointSock::recv_data(int peer_sock, char *ptr, int avail) {
  return recv(peer_sock, ptr, avail, 0);
}

int EndpointSock::send_data(int peer_sock, const char *ptr, int remain, const char *) {
  SD_LOG(LOG_DEBUG, "EndpointSock send_data");
  return send(peer_sock, ptr, remain, MSG_NOSIGNAL);
}
