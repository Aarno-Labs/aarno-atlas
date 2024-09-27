#ifndef NW_H
#define NW_H
#include <sys/types.h>
#include <openssl/ssl.h>

int32_t diencl_socket (int port);
// int32_t diencl_accept(int32_t welcome_socket, SSL_CTX *ssl_context);
int32_t diencl_accept(int32_t welcome_socket);

int32_t diencl_accept_ssl(int32_t sock,
                          const char *ssl_certificate_file,
                          const char *ssl_key_file);

int32_t dienc_recv(uint32_t sock, void *data, uint32_t len);
int32_t dienc_send(uint32_t sock, void *data, uint32_t len);

char *recv_file(int32_t n_socket, uint32_t *s);
int32_t recv_data(int32_t sock, uint8_t *b, uint32_t num);
int32_t recv_chunk_data(int32_t n, uint32_t num, uint8_t a);
int32_t send_public_key(int32_t sock, uint8_t *key, uint32_t size);
int32_t recv_client_key(int32_t sock, uint8_t *key, uint32_t size);

SSL_CTX* create_context(bool isServer);


#endif
