#include <sstream>
#include <array>
#include <math.h>
#include "Enclave_t.h"
#include "sgx_tcrypto.h"
#include "sgx_includes.h"
#include "sgx_funcs.h"
#include "sgx_structs.h"

#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>

#include <string>

#include "sgx_defs.h"
#include "sgx_thread.h"
#include <stdio.h>
#include "dh/tools.h"
#include "dh/tweetnacl.h"
#include "Enclave_t.h"
#include "sgx_trts.h"
#include <string.h>  
#include <stdlib.h>  
#include <vector>
#include <stack>
#include <string>
#include <assert.h>
#include <sgx_thread.h>

#include "Ocall_wrappers.h"
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "log/sgx_log.h"


extern "C" int __cxa_thread_atexit(void (*dtor)(void *), void *obj, void *dso_symbol) {return 0;};


// g++ things :)
extern "C" {

  typedef struct JSRuntime JSRuntime;
  typedef struct JSContext JSContext;

  // quickjs context for each thread
  typedef struct {
    JSContext *quickjs_enclave_ctx;
    JSRuntime *quickjs_enclave_rt;
  } BootStrapReturn;
  
  BootStrapReturn bootstrap_qjs();
  void CleanupQJS(BootStrapReturn *bs_return);
  void js_std_loop(JSContext *ctx);
  void qjs_execute_code(BootStrapReturn *bs_return, char *buffer, int32_t len);
  void qjs_add_arguments(BootStrapReturn *bs_return, char *serialized_args, int32_t len);
  void
  random_bytes(uint8_t *a, int32_t len)
  {
    sgx_read_rand(a, len);
  }
}

void
randombytes(uint8_t *a, uint8_t b)
{
  sgx_read_rand(a, b);
}


void
ecall_init(FILE *stdi, FILE *stdo, FILE *stde) {
  stdin = stdi;
  stdout = stdo;
  stderr = stde;
}

extern const char *evaluator;
extern size_t evaluator_len;

static void init_openssl()
{
  OpenSSL_add_ssl_algorithms();
  OpenSSL_add_all_ciphers();
  SSL_load_error_strings();
}

SSL_CTX *create_context()
{
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  method = TLSv1_2_method();

  ctx = SSL_CTX_new(method);
  if (!ctx) {
    LOG_ERROR("Unable to create SSL context");
    exit(EXIT_FAILURE);
  }
  return ctx;
}



// Use unique_ptr with SSL_CTX
using SSL_CTX_PTR = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
bool use_ssl;
SSL_CTX_PTR ssl_ctx {nullptr, &SSL_CTX_free};


/* inet_aton from https://android.googlesource.com/platform/bionic.git/+/android-4.0.1_r1/libc/inet/inet_aton.c */
static int inet_aton(const char *cp, struct in_addr *addr)
{
	u_long val, base, n;
	char c;
	u_long parts[4], *pp = parts;

	for (;;) {
		/*
		 * Collect number up to ``.''.
		 * Values are specified as for C:
		 * 0x=hex, 0=octal, other=decimal.
		 */
		val = 0; base = 10;
		if (*cp == '0') {
			if (*++cp == 'x' || *cp == 'X')
				base = 16, cp++;
			else
				base = 8;
		}
		while ((c = *cp) != '\0') {
			if (isascii(c) && isdigit(c)) {
				val = (val * base) + (c - '0');
				cp++;
				continue;
			}
			if (base == 16 && isascii(c) && isxdigit(c)) {
				val = (val << 4) + 
					(c + 10 - (islower(c) ? 'a' : 'A'));
				cp++;
				continue;
			}
			break;
		}
		if (*cp == '.') {
			/*
			 * Internet format:
			 *	a.b.c.d
			 *	a.b.c	(with c treated as 16-bits)
			 *	a.b	(with b treated as 24 bits)
			 */
			if (pp >= parts + 3 || val > 0xff)
				return (0);
			*pp++ = val, cp++;
		} else
			break;
	}
	/*
	 * Check for trailing characters.
	 */
	if (*cp && (!isascii(*cp) || !isspace(*cp)))
		return (0);
	/*
	 * Concoct the address according to
	 * the number of parts specified.
	 */
	n = pp - parts + 1;
	switch (n) {

		case 1:				/* a -- 32 bits */
			break;

		case 2:				/* a.b -- 8.24 bits */
			if (val > 0xffffff)
				return (0);
			val |= parts[0] << 24;
			break;

		case 3:				/* a.b.c -- 8.8.16 bits */
			if (val > 0xffff)
				return (0);
			val |= (parts[0] << 24) | (parts[1] << 16);
			break;

		case 4:				/* a.b.c.d -- 8.8.8.8 bits */
			if (val > 0xff)
				return (0);
			val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
			break;
	}
	if (addr)
		addr->s_addr = htonl(val);
	return (1);
}


int aarno_close(int sock) {
  return sgx_close(sock);
}

#define	INADDR_NONE		((unsigned long int) 0xffffffff)

in_addr_t inet_addr(const char *cp)
{
	struct in_addr val;

	if (inet_aton(cp, &val))
		return (val.s_addr);
	return (INADDR_NONE);
}

static int create_socket_client(const char *ip, uint32_t port) 
{
	int sockfd;
	struct sockaddr_in dest_addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0) {
		printe("socket");
		exit(EXIT_FAILURE);
	}

	dest_addr.sin_family=AF_INET;
	dest_addr.sin_port=htons(port);
	dest_addr.sin_addr.s_addr = (long)inet_addr(ip);
	memset(&(dest_addr.sin_zero), '\0', 8);

	printl("Connecting...");
	if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) == -1) {
		printe("Cannot connect");
        exit(EXIT_FAILURE);
	}

	return sockfd;
}

std::string sediment_signing_key_;

sgx_thread_mutex_t sock_mutex  = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_cond_t  sock_variable = SGX_THREAD_COND_INITIALIZER;

std::stack<int> accepted_sockets;

int SetupSSLContext(SSL_CTX &ssl_ctx,
                    const char *ssl_certificate,
                    const char *ssl_key) {
  BIO *cert_bio = BIO_new_mem_buf(ssl_certificate, -1);
  X509 *cert = PEM_read_bio_X509_AUX(cert_bio, NULL, NULL, NULL);
  SSL_CTX_use_certificate(&ssl_ctx, cert);

  X509 *ca;
  int r;
  unsigned long err;
  r = SSL_CTX_clear_chain_certs(&ssl_ctx);
  while ((ca = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL))
         != NULL) {
    r = SSL_CTX_add0_chain_cert(&ssl_ctx, ca);
    /*
     * Note that we must not free ca if it was successfully added to
     * the chain (while we must free the main certificate, since its
     * reference count is increased by SSL_CTX_use_certificate).
     */
    if (!r) {
      X509_free(ca);
      LOG_ERROR("SSL: r=%d PEM_read_bio_PrivateKey", r);
      //                ERR_print_errors_fp(stderr);
      return EXIT_FAILURE;
    }
  }
  /* When the while loop ends, it's usually just EOF. */
  err = ERR_peek_last_error();
  if (ERR_GET_LIB(err) == ERR_LIB_PEM
      && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)
    ERR_clear_error();

  BIO *key_bio = BIO_new_mem_buf(ssl_key, -1);
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL);
  if (NULL == pkey) {
    LOG_ERROR("SSL: %r=%d PEM_read_bio_PrivateKey", r);
    //          ERR_print_errors_fp(stderr);
    return EXIT_FAILURE;
               }
  int ret = SSL_CTX_use_PrivateKey(&ssl_ctx, pkey);
  if (!ret) {
    LOG_ERROR("SSL: ret=%d PEM_read_bio_PrivateKey ret=%d", ret);
    //          ERR_print_errors_fp(stderr);
    return EXIT_FAILURE;
  }
  EVP_PKEY_free(pkey);
  LOG_INFO("SSL: Using given cert and key->Done");
  return EXIT_SUCCESS;
}

uint8_t ecall_setup_ssl_context(const char *ssl_certificate,
                                const char *ssl_key,
                                const char *sediment_signing_key
                                ) {
    init_openssl();
    ssl_ctx = {create_context(), &SSL_CTX_free};
    if (!ssl_ctx) {
      LOG_ERROR("SSL: Unable to create ssl context");
      return false;
    }
    const auto setup_ssl = SetupSSLContext(*ssl_ctx.get(),
                                           ssl_certificate, ssl_key);
    if (EXIT_FAILURE == setup_ssl) {
      LOG_ERROR("SSL: setup_ssl=%d Setup SSL context failed", setup_ssl);
      return false;
    }

    sediment_signing_key_ = sediment_signing_key;
    return true;
}

uint8_t ecall_setup_ssl_context(const char *sediment_signing_key) {
    sediment_signing_key_ = sediment_signing_key;
    return true;
}
