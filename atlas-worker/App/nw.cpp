#include <netdb.h>
#include <err.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>  
#include <vector>
#include <thread>       
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include "funcs.h"
#include "nw.h"
#include <stdio.h>
#include <time.h>
#include <stdio.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "sgx_tcrypto.h"

#include <map>

#include <openssl/err.h>

#define LOCATION __LINE__,__FILE__,__func__
struct timespec tnw_start{0, 0}, tnw_stop{0, 0};
double network_time = 0.0f;


int32_t
recv_data(int32_t sock, uint8_t *buffer, uint32_t number)
{
	int32_t rx_bytes;
	int32_t tmp_bytes;
	rx_bytes = 0;
	tmp_bytes = 0;
	printf("%s:%d %s [number=%u]\n", __FILE__, __LINE__, __FUNCTION__, number);
	
	while (rx_bytes < (int32_t)number) {
          tmp_bytes = dienc_recv(sock, &buffer[rx_bytes], number-rx_bytes);
		if (tmp_bytes <= 0) 
            return -1;
		rx_bytes += tmp_bytes;
	}
	return rx_bytes;
}

int32_t
diencl_socket(int port)
{
	/* declaration */
	int ws;
	int bind_result;
	int listen_result;
	// used for setting keepalive flag
	int optval;
	struct sockaddr_in server_addr;
	// init code
	// Set the option active
	optval = 1;
	// reset values
	bind_result = listen_result = 0;
	memset(&server_addr, 0, sizeof(struct sockaddr_in));
	// setup the new socket
	ws = socket(AF_INET, SOCK_STREAM, 0);
	if (ws == -1) {
		fprintf(stdout, "Failed to Initialize socket: Line %d File %s Func %s\n", LOCATION);
		abort();
	}
	if (setsockopt(ws, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
		fprintf(stdout, "Failed to set KEEP_ALIVE for socket: Line %d File %s Func %s\n", LOCATION);
		abort();
	}
        printf("%s:%d %s port=%d done\n", __FILE__, __LINE__, __FUNCTION__, port);
    
        
	// make port reusable
	setsockopt(ws, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	memset(server_addr.sin_zero, '\0', sizeof(server_addr.sin_zero));
	// bind to the port
	bind_result = bind(ws, (struct sockaddr *) &server_addr, sizeof(server_addr));
	if (bind_result == -1) {
		fprintf(stdout, "Failed to bind socket: Line %d File %s Func %s\n", LOCATION);
		abort();
	}
	// listen to the socket
	listen_result = listen(ws, 1);
	if (listen_result == -1) {
		fprintf(stdout, "Failed to listen socket: Line %d File %s Func %s\n", LOCATION);
		abort();
	}
	return ws;
}

int32_t
diencl_accept(int32_t ws) {
	int32_t new_socket;
	struct sockaddr_in client;
	socklen_t len = sizeof(client);
	memset(&client, 0, sizeof(struct sockaddr_in));
        printf("%s:%d %sc accept ws=%d accept wait\n", __FILE__, __LINE__, __FUNCTION__, ws);
	new_socket = accept(ws, (struct sockaddr *)&client, &len);
        printf("%s:%d %sc accept new_socket=%d accept done\n", __FILE__, __LINE__, __FUNCTION__, new_socket);
	if (new_socket == -1) {
		printf("%d\n", ws);
		fprintf(stdout, "Failed to accept socket: Line %d File %s Func %s\n", LOCATION);
		abort();
	}
        
        printf("%s:%d %sc diencl_accept done\n", __FILE__, __LINE__, __FUNCTION__);
	return new_socket;
}

using UPtrSSLCtx = std::unique_ptr<SSL, decltype(std::free) *>;

std::map<int32_t, UPtrSSLCtx> socket_to_ssl_;


int32_t
diencl_accept_ssl(int32_t socket,
              const char *ssl_certificate_file,
              const char *ssl_key_file) {
  SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
  if (ssl_ctx == NULL) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  /* Set the key and cert */
  if (SSL_CTX_use_certificate_chain_file(ssl_ctx, ssl_certificate_file) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_PrivateKey_file(ssl_ctx, ssl_key_file, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  UPtrSSLCtx ssl {SSL_new(ssl_ctx), std::free};
  printf("%s:%d %s SSL_new ssl=%p done\n", __FILE__, __LINE__, __FUNCTION__, ssl.get());
  SSL_set_fd(ssl.get(), socket);
        
  /* Wait for SSL connection from the client */
  if (SSL_accept(ssl.get()) <= 0) {
    ERR_print_errors_fp(stderr);
    abort();
  }

  socket_to_ssl_.insert({socket, std::move(ssl)});

  printf("%s:%d %sc diencl_accept done\n", __FILE__, __LINE__, __FUNCTION__);
  return 0;
}

int32_t
dienc_recv(uint32_t socket, void *data, uint32_t len)
{
	int32_t d;
	//clock_gettime(CLOCK_REALTIME, &tnw_start);
        printf("%s:%d %s [len=%u]\n", __FILE__, __LINE__, __FUNCTION__, len);

        auto ssl = socket_to_ssl_.find(socket);
        if(std::end(socket_to_ssl_) != ssl) {
          d = SSL_read(ssl->second.get(), data, len);
          if(d < 0) {
            ERR_print_errors_fp(stderr);
          };
        } else {
          d = recv(socket, data, len, MSG_NOSIGNAL);
        }
                   
	printf("%s:%d %s [len=%u d=%d]\n", __FILE__, __LINE__, __FUNCTION__, len, d);
	//clock_gettime(CLOCK_REALTIME, &tnw_stop);
	//network_time += get_time_diff(tnw_stop, tnw_start) / 1000; 
	return d;
}

int32_t
dienc_send(uint32_t socket, void *data, uint32_t len)
{
	int32_t d;
	//clock_gettime(CLOCK_REALTIME, &tnw_start);
        auto ssl = socket_to_ssl_.find(socket);
        if(std::end(socket_to_ssl_) != ssl) {
          d = SSL_write(ssl->second.get(), data, len);
          if(d < 0) {
            ERR_print_errors_fp(stderr);
          }
        } else {
          d = send(socket, data, len, MSG_NOSIGNAL);
        }
	//clock_gettime(CLOCK_REALTIME, &tnw_stop);
	//network_time += get_time_diff(tnw_stop, tnw_start) / 1000; 
	return d;
}

int32_t
recv_client_key(uint32_t sock, uint8_t *key, uint32_t size)
{
  printf("%s:%d %s [size=%u]\n", __FILE__, __LINE__, __FUNCTION__, size);
  return dienc_recv(sock, key, size);
}

int32_t
send_public_key(uint32_t sock, uint8_t *key, uint32_t size)
{
  printf("%s:%d %s [size=%u]\n", __FILE__, __LINE__, __FUNCTION__, size);
  return dienc_send(sock, key, size);
}

void
ocall_send_packet(int32_t sock, uint8_t *pkt, int32_t len)
{
	int32_t tmp_bytes, rx_bytes, var;
	rx_bytes = tmp_bytes = 0;
	while (rx_bytes != (int32_t)len) {
		var = len - rx_bytes;
		printf("[%s:%d %s]\n", __FILE__, __LINE__, __FUNCTION__);
		dienc_send(sock, &var, sizeof(uint32_t));
		printf("[%s:%d %s]\n", __FILE__, __LINE__, __FUNCTION__);
		tmp_bytes = dienc_send(sock, &pkt[rx_bytes], (uint32_t)(len-rx_bytes));
            
        if (tmp_bytes == -1) {
#ifdef DEBUG
            perror("Broken Pipe");
#endif
            break;
        }
		rx_bytes += tmp_bytes;
		printf("[%s:%d %s tmp_bytes=%d rx_bytes=%d, len=%d]\n", __FILE__, __LINE__, __FUNCTION__,
		       tmp_bytes, rx_bytes, len);
	}
}
