#include <sstream>
#include <array>
#include <math.h>

#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>

#include <string>
#include <iomanip>

#include <stdio.h>
#include <string.h>  
#include <stdlib.h>  
#include <vector>
#include <stack>
#include <string>
#include <memory>
#include <assert.h>


#ifndef AARNO_SIMPLE
#include "Enclave_t.h"
#include "sgx_tcrypto.h"
#include "sgx_includes.h"
#include "sgx_funcs.h"
#include "sgx_structs.h"

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
#include <assert.h>
#include <sgx_thread.h>

#include "Ocall_wrappers.h"

#include "log/sgx_log.h"
#else
#include <arpa/inet.h>
#endif

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/rand.h>

// #define DEBUG_LOG 1
#include "../utils/log/sgx_log.h"



thread_local std::string serial_response_;

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
  append_results(const char *b, const uint8_t *serial_response, const size_t serial_size)
  {
    serial_response_ = std::string((const char *)serial_response, serial_size);
  }

}

extern int aarno_close(int sock);

extern const char *evaluator;
extern size_t evaluator_len;
/*
 * The first function that inits the qjs VM, stores the context in global variable
 * and preloads the modules
 */
static EVP_PKEY *generatePrivateKey()
{
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  EVP_PKEY_keygen_init(pctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
  EVP_PKEY_keygen(pctx, &pkey);
  return pkey;
}

static X509 *generateCertificate(EVP_PKEY *pkey)
{
  X509 *x509 = X509_new();
  X509_set_version(x509, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x509), 0);
  X509_gmtime_adj(X509_get_notBefore(x509), 0);
  X509_gmtime_adj(X509_get_notAfter(x509), (long)60*60*24*365);
  X509_set_pubkey(x509, pkey);

  X509_NAME *name = X509_get_subject_name(x509);
  X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"US", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"YourCN", -1, -1, 0);
  X509_set_issuer_name(x509, name);
  X509_sign(x509, pkey, EVP_md5());
  return x509;
}

static void init_openssl()
{
  OpenSSL_add_ssl_algorithms();
  OpenSSL_add_all_ciphers();
  SSL_load_error_strings();
}

// SGX OpenSSL is older, it's create context causes warnings
// with simple server, so let each uses its best SSL
SSL_CTX *create_context();

// Use unique_ptr with SSL_CTX
using SSL_CTX_PTR = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
bool send_unencrypted_;
bool use_ssl;
SSL_CTX_PTR ssl_ctx {nullptr, &SSL_CTX_free};

// SEDIMENT signing key
std::vector<uint8_t> authKey;


class Sockets {
public:
  class ISocket {
  public:
    explicit ISocket(int sock) : sock(sock) {};
    virtual int read(void *buf, int buf_size) = 0;
    virtual int write(const void *buf, int buf_size) = 0;
    virtual int finish_accept() = 0;
    virtual ~ISocket() {
      if (sock > 0) {
        close(sock);
      }
    }
    int sock;
  };

  class SSLSocket : public ISocket {
  public:
    explicit SSLSocket(int sock) :
      ISocket(sock),
      ssl {SSL_new(ssl_ctx.get()), SSL_free}
    {};

    virtual ~SSLSocket() {
      SSL_shutdown(ssl.get());
    }

    int read(void *buf, int read_size) override {
      return SSL_read(ssl.get(),
                      buf,
                      read_size);
    }

    int write(const void *buf, const int read_size) override {
      return SSL_write(ssl.get(),
                       buf,
                       read_size);
    }

    virtual int finish_accept() override {
      LOG_DEBUG("start finish_accept ssl_ctx=%p ssl=%p sock=%d", ssl_ctx.get(), ssl.get(), sock);
      SSL_set_fd(ssl.get(), sock);

      if (SSL_accept(ssl.get()) <= 0) {
        LOG_ERROR("SSL FAILED client=%d", sock);
        return -1;
      }
      LOG_DEBUG("SSL_accept done %p %d", ssl.get(), sock);
          
      return 1;
    }

  private:
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl;
    bool ssl_initialized_client = false;
  };

  class PlainSocket : public ISocket {
  public:
    explicit PlainSocket(int sock) : ISocket(sock) {}

    int read(void *buf, int buf_size) override {
      return ::read(sock, buf, buf_size);
    }

    int write(const void *buf, const int buf_size) override {
      const char *p = (const char *)buf;
      int total_sent = 0;
      while(total_sent != buf_size) {
        auto single_send = ::write(sock, const_cast<void *>(buf), buf_size);
        if(single_send < 0) {
          LOG_WARN("send failed %ld\n", single_send);
          return single_send;
        }
        total_sent += single_send;
        p += single_send;
      }
      return total_sent;
    }

    int finish_accept() override {
      return 1;
    }

    // // EndpointSock *FinishClientConnection(int sock, const Endpoint &ep) override {
    // //     return new EndpointSock(ep, sock);
    // // }

  };
};

auto RecvSizedBuffer(Sockets::ISocket &socket,
                     std::string &buffer_str,
                     const char msg[]) -> int {
  uint32_t buffer_len = 0;
  const auto read_buf_len = socket.read(
                                        (void *)&buffer_len,
                                        sizeof(buffer_len));
  LOG_DEBUG("[%s]"
            " fd=%d"
            " read_buf_len=%u"
            " buffer_len=%u",
            msg,
            socket.sock,
            read_buf_len,
            buffer_len);

  if(read_buf_len <= 0){
    LOG_ERROR("[%s]"
              " fd=%d"
              " read_buf_len=%u",
              msg,
              socket.sock,
              read_buf_len);
    return -1;
  }

  buffer_str.resize(buffer_len * sizeof(unsigned char));
  auto *buffer = (uint8_t *)&buffer_str.data()[0];
  uint32_t total_read = 0;

  while (total_read < buffer_len) {
    LOG_DEBUG("[%s] fd=%d total_read=%u buffer_len=%u",
              msg,
              socket.sock,
              total_read,
              buffer_len);
    const auto read_buf =
      socket.read(buffer + total_read,
                  buffer_len - total_read);
    LOG_DEBUG("[%s]"
              " fd=%d"
              " read_buf=%d",
              msg,
              socket.sock,
              read_buf);

    if(read_buf <= 0){
      LOG_INFO("[%s]"
               " fd=%d"
               " read_buf=%d",
               msg,
               socket.sock,
               read_buf);
      return -1;
    }
    total_read += read_buf;
  }
  LOG_DEBUG("[%s][done] fd=%d total_read=%u buffer_len=%u",
            msg, socket.sock, total_read, buffer_len);
  return total_read;

}

auto RecvSizedBufferShort(Sockets::ISocket &socket,
                          std::string &buffer_str,
                          const char msg[]) -> int {
  uint16_t buffer_len_net = 0;
  const auto read_buf_len = socket.read(
                                        (void *)&buffer_len_net,
                                        sizeof(buffer_len_net));
  const uint16_t buffer_len = ntohs(buffer_len_net) - 2; // includes total
  LOG_DEBUG("[%s]"
            " fd=%d"
            " read_buf_len=%u"
            " buffer_len=%u",
            msg,
            socket.sock,
            read_buf_len,
            buffer_len);

  if(read_buf_len <= 0){
    LOG_ERROR("[%s]"
              " fd=%d"
              " read_buf_len=%u",
              msg,
              socket.sock,
              read_buf_len);
    return -1;
  }

  buffer_str.resize(buffer_len * sizeof(unsigned char));
  auto *buffer = (uint8_t *)&buffer_str.data()[0];
  uint32_t total_read = 0;

  while (total_read < buffer_len) {
    LOG_DEBUG("[%s] fd=%d total_read=%u buffer_len=%u",
              msg,
              socket.sock,
              total_read,
              buffer_len);
    const auto read_buf =
      socket.read(buffer + total_read,
                  buffer_len - total_read);
    LOG_DEBUG("[%s]"
              " fd=%d"
              " read_buf=%d",
              msg,
              socket.sock,
              read_buf);

    if(read_buf <= 0){
      LOG_INFO("[%s]"
               " fd=%d"
               " read_buf=%d",
               msg,
               socket.sock,
               read_buf);
      return -1;
    }
    total_read += read_buf;
  }
  LOG_DEBUG("[%s][done] fd=%d total_read=%u buffer_len=%u",
            msg, socket.sock, total_read, buffer_len);
  return total_read;

}

in_addr_t inet_addr(const char *cp);

static int create_socket_client(const char *ip, uint32_t port) 
{
  int sockfd;
  struct sockaddr_in dest_addr;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd < 0) {
    LOG_ERROR("socket failed");
    return -1;
  }

  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
  dest_addr.sin_addr.s_addr = (long)inet_addr(ip);
  memset(&(dest_addr.sin_zero), '\0', 8);

  LOG_DEBUG("Connecting...");
  if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) == -1) {
    LOG_ERROR("Cannot connect");
    return -1;
  }

  return sockfd;
}


// This is a helper to make sure the EVP_MD_CTX is cleaned up
// Like a BOOST_SCOP_EXIT (not bringing Boost into the Enclave)
class Scope_EVP_MD_CTX_Destroy {
public:
  Scope_EVP_MD_CTX_Destroy(EVP_MD_CTX &evp_md_ctx)
    : evp_md_ctx_(evp_md_ctx) {};
  virtual ~Scope_EVP_MD_CTX_Destroy() {
    EVP_MD_CTX_destroy(&evp_md_ctx_);
  };
private:
  EVP_MD_CTX &evp_md_ctx_;
};



int SHA256_Sign(const char *msg, size_t mlen, uint8_t *&sig, size_t &slen, EVP_PKEY *signingKey) {
  if (!msg) {
    LOG_ERROR("NULL msg");
    return -1;
  }

  if (!mlen) {
    LOG_ERROR("zero mlen");
    return -1;
  }

  sig = nullptr;
  slen = 0;

  EVP_MD_CTX *evp_md_ctx = EVP_MD_CTX_create();

  if(evp_md_ctx == nullptr) {
    LOG_ERROR("EVP_MD_CTX_create failed");
    return -1;
  }
  
  auto evp_md_ctx_delete =
    std::unique_ptr<Scope_EVP_MD_CTX_Destroy>(new Scope_EVP_MD_CTX_Destroy(*evp_md_ctx));

  constexpr auto sha256_ = "SHA256";
  const EVP_MD *md = EVP_get_digestbyname(sha256_);
  if (md == nullptr) {
    LOG_ERROR("EVP_get_digestbyname for %s failed, error %ld", sha256_, ERR_get_error());
    return -1;
  }

  const auto evp_digestinit = EVP_DigestInit_ex(evp_md_ctx, md, nullptr);
  if (evp_digestinit != 1) {
    LOG_ERROR("EVP_DigestInit_ex for %s failed, rc=%d error %ld", sha256_, evp_digestinit,
              ERR_get_error());
    return -1;
  }

  const auto evp_digestsign = EVP_DigestSignInit(evp_md_ctx, nullptr, md, nullptr, signingKey);
  if (evp_digestsign != 1) {
    LOG_ERROR("EVP_DigestSign for %s failed, rc=%d error %ld", sha256_, evp_digestinit, ERR_get_error());
    return -1;
  }

  const auto evp_digestsignupdate = EVP_DigestSignUpdate(evp_md_ctx, msg, mlen);
  if (evp_digestsign != 1) {
    LOG_ERROR("EVP_DigestSignUpdate for %s failed, rc=%d error %ld", sha256_, evp_digestsignupdate,
              ERR_get_error());
    return -1;
  }

  size_t required_size = 0;
  // Get the required size
  const auto evp_digest_sign_final0 = EVP_DigestSignFinal(evp_md_ctx, nullptr, &required_size);
  if (evp_digest_sign_final0 != 1) {
    LOG_ERROR("EVP_DigestSignFinal (size) for %s failed, rc=%d error %ld", sha256_,
              evp_digest_sign_final0,
              ERR_get_error());
    return -1;
  }

  if (required_size <= 0) {
    LOG_ERROR("EVP_DigestSignFinal (size) for %s failed, rc=%d required_size=%ld error %ld", sha256_,
              evp_digest_sign_final0,
              required_size, ERR_get_error());
    return -1;
  }

  sig = (uint8_t *) OPENSSL_malloc(required_size);
  if (sig == nullptr) {
    LOG_ERROR("OPENSSL_malloc failed, error %ld", ERR_get_error());
    return -1;
  }

  slen = required_size;
  const auto evp_digest_sign_final = EVP_DigestSignFinal(evp_md_ctx, sig, &slen);
  if (evp_digest_sign_final != 1) {
    LOG_ERROR("EVP_DigestSignFinal (final) for %s failed, rc=%d required_size=%ld error %ld", sha256_,
              evp_digest_sign_final,
              required_size, ERR_get_error());
    return -1;
  }

  return 0;
}


std::string sediment_signing_key_;

constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

std::string hexStr(const std::string &data)
{
  std::string s(data.size() * 2, ' ');
  for (int i = 0; i < data.size(); ++i) {
    s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
    s[2 * i + 1] = hexmap[data[i] & 0x0F];
  }
  return s;
}

std::string hexStr(const std::array<unsigned char, 32> &data)
{
  std::string s(data.size() * 2, ' ');
  for (int i = 0; i < data.size(); ++i) {
    s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
    s[2 * i + 1] = hexmap[data[i] & 0x0F];
  }
  return s;
}

std::string PassportCheckMessage(const std::vector<uint8_t> &key,
                                 const std::array<unsigned char, 32> &nonce,
                                 const uint8_t message_id,
                                 const uint32_t timestamp,
                                 const std::string &device_id,
                                 const std::string passport_bytes) {
  const uint16_t digest_len = 32;
  const uint16_t nonce_len = nonce.size();
  const uint8_t device_id_len = device_id.size();

  uint16_t total_msg_len = 0;
  uint16_t sig_sha256_len = 256;

  const auto idx_msg_digest_len_end = sizeof(total_msg_len) + sizeof(digest_len);
  const auto idx_digest_end = idx_msg_digest_len_end + digest_len;
  const auto idx_msg_header_end = idx_digest_end
    + sizeof(nonce_len)
    + nonce_len
    + sizeof(message_id)
    + sizeof(timestamp)
    + sizeof(device_id_len)
    + device_id_len;
  total_msg_len = idx_msg_header_end
    + passport_bytes.size()
    + sizeof(sig_sha256_len)
    + sig_sha256_len;

  auto digest = std::string(digest_len, 'R');

  std::stringstream message;

  // Enclave returns 32 bits for htons, so force to 16 bits
  const uint16_t message_len_network = htons(total_msg_len);
  // Enclave returns 32 bits for htons, so force to 16 bits
  const uint16_t digest_len_network = htons(digest_len);

  message.write(reinterpret_cast<const char *>(&message_len_network), sizeof(message_len_network));
  LOG_DEBUG("total_msg_len=%d, message_len_network=%d message.size()=%lu",
            total_msg_len,
            message_len_network,
            message.str().size());

  message.write(reinterpret_cast<const char *>(&digest_len_network), sizeof(digest_len_network));
  LOG_DEBUG("digest_len=%d digest_len_network=%d message.size()=%lu",
            digest_len,
            digest_len_network,
            message.str().size());

  // placeholder values for now, calculate actual digest when rest of message is completed
  message.write(digest.data(), digest_len);
  const auto digest_str = hexStr(digest);
  LOG_DEBUG("message.size()=%lu digest=%s", message.str().size(), digest_str.c_str());

  // Enclave returns 32 bits for htons, so force to 16 bits
  const uint16_t nonce_len_network = htons(nonce_len);
  message.write(reinterpret_cast<const char *>(&nonce_len_network), sizeof(nonce_len_network));
  LOG_DEBUG("[nonce_len=%d nonce_len_network=%d message.size()=%lu",
            nonce_len,
            nonce_len_network,
            message.str().size());

  const auto nonce_str = hexStr(nonce);
  message.write(reinterpret_cast<const char *>(nonce.data()), nonce_len);
  LOG_DEBUG("nonce=%s message.size()=%lu", nonce_str.c_str(), message.str().size());

  message.write(reinterpret_cast<const char *>(&message_id), sizeof(message_id));
  const uint32_t timestamp_network = htonl(timestamp);
  message.write(reinterpret_cast<const char *>(&timestamp_network), sizeof(timestamp_network));
  LOG_DEBUG("message_id=%d message.size()=%lu", message_id,  message.str().size());

  message.write(reinterpret_cast<const char *>(&device_id_len), sizeof(device_id_len));
  LOG_DEBUG("device_id_len=%u message.size()=%lu", device_id_len, message.str().size());
  message.write(device_id.data(), device_id_len);
  LOG_TRACE("device_id=%s message.size()=%lu", device_id.c_str(), message.str().size());

  message << passport_bytes;
  LOG_DEBUG("passport_bytes.size()=%lu message.size()=%lu", passport_bytes.size(), message.str().size());

  EVP_PKEY *signingKey = nullptr;
  BIO *bio_private = BIO_new_mem_buf(sediment_signing_key_.c_str(), -1);
  PEM_read_bio_PrivateKey(bio_private, &signingKey, 0, nullptr);
  BIO_flush(bio_private);
  BIO_free(bio_private);

  const auto message_bytes = message.str();
  uint8_t *sig = nullptr;
  size_t sig_len = 0;
  const auto sign_result = SHA256_Sign(
                                       message_bytes.c_str() + idx_msg_header_end,
                                       message_bytes.size() - idx_msg_header_end,
                                       sig,
                                       sig_len,
                                       signingKey);

  EVP_PKEY_free(signingKey);
  signingKey = nullptr;

  std::unique_ptr<uint8_t, decltype(std::free) *> passport_sig_guard{sig, std::free};

  if(0 != sign_result || sig_len != sig_sha256_len) {
    LOG_ERROR("SH256 signing failed sign_result=(%d) expected (0) sig_len=(%lu) expected (%d)",
              sign_result, sig_len, sig_sha256_len);
    return "";
  }

  sig_sha256_len = sig_len;
  // Enclave returns 32 bits for htons, so force to 16 bits
  const uint16_t sig_len_network = htons(sig_len);
  message.write(reinterpret_cast<const char *>(&sig_len_network), sizeof(sig_len_network));
  LOG_DEBUG("sig_sha256_len=%d  sig_len_network=%u message.size()=%lu", sig_sha256_len, sig_len_network, message.str().size());
  message.write(reinterpret_cast<const char *>(sig), sig_sha256_len);

  auto final_message_bytes = message.str();

  LOG_DEBUG("[final_message_bytes.size()=%lu", final_message_bytes.size());

  unsigned int result_size = 0;
  const auto *hmac = reinterpret_cast<const unsigned char *>(final_message_bytes.c_str()) + idx_digest_end;
  const auto hmac_size = total_msg_len - idx_digest_end;
  unsigned char *result = HMAC(EVP_sha256(),
                               key.data(), key.size(),
                               hmac,
                               hmac_size,
                               nullptr,
                               &result_size);

  if (digest_len != result_size) {
    LOG_ERROR("HMAC SIZE error result_size[%u] expected[%u]", result_size, digest_len);
  }

  final_message_bytes.replace(idx_msg_digest_len_end, result_size, (const char *)result);
  return final_message_bytes;
}

time_t getTimestamp() {
  long ms;  // Milliseconds
  time_t s; // Seconds
  struct timespec spec;

  clock_gettime(CLOCK_REALTIME, &spec);

  s = spec.tv_sec;
  ms = round(spec.tv_nsec / 1.0e6); // Convert nanoseconds to milliseconds
  if (ms > 999) {
    s++;
    ms = 0;
  }
  return s;
}


// This is a helper to make sure the BootStrapReturn is cleanedup
// Like a BOOST_SCOP_EXIT (not bringing Boost into the Enclave)
class ScopeCleanupQJS {
public:
  ScopeCleanupQJS(BootStrapReturn &bs_return)
    : bs_return_(bs_return) {};
  virtual ~ScopeCleanupQJS() {
    LOG_DEBUG("~ScopeCleanupQJ");
    js_std_loop(bs_return_.quickjs_enclave_ctx);
    CleanupQJS(&bs_return_);
  };
private:
  BootStrapReturn &bs_return_;
};



static bool attest_sediment(Sockets::ISocket &client_socket,
                            bool use_ssl) {
  std::string passport_buffer_str{};
  const auto passport_total_read = RecvSizedBuffer(client_socket, passport_buffer_str, "passport");
  if (passport_total_read <= 0) {
    return false;
  }

  std::string device_id_buffer_str {};
  const auto device_id_total_read =
    RecvSizedBuffer(client_socket,
                    device_id_buffer_str,
                    "device_id");
  if (device_id_total_read <=0) {
    return false;
  }
  LOG_TRACE("[device_id=%s]", device_id_buffer_str.c_str());
  
  int firewall_sock = create_socket_client("192.168.0.22", 8000);
  std::unique_ptr<Sockets::ISocket> firewall_socket;
  if (use_ssl) {
    firewall_socket.reset(new Sockets::SSLSocket(firewall_sock));
  } else {
    firewall_socket.reset(new Sockets::PlainSocket(firewall_sock));
  }
  
  // nonce size is 32 bytes
  std::array<unsigned char, 32> nonce;
  
  const auto rand_result = RAND_bytes(nonce.data(), nonce.size());
  if (1 != rand_result) {
    LOG_ERROR("RAND_bytes failed rand_result={%d} expected (1)", rand_result);
    return false;
  }

  const auto msg_timestamp = getTimestamp();
  auto passport_check_bytes = PassportCheckMessage(authKey,
                                                   nonce,
                                                   8, // MessageID = PASSPORT_CHECK = 8
                                                   msg_timestamp,
                                                   device_id_buffer_str,
                                                   passport_buffer_str);

  const auto firewall_send =
    firewall_socket->write(passport_check_bytes.c_str(),
                          passport_check_bytes.size());
  
  LOG_DEBUG("[sent passport firewall_send=%d]", firewall_send);


  // Read the response and just check the grant status
  // no need to decode the whole message
  std::string permission_msg;
  auto passcheck_read_result = RecvSizedBufferShort(*firewall_socket,
                                                    permission_msg,
                                                    "passcheck_response");

  if(permission_msg.size() == 0) {
    LOG_INFO("invalid permission size=(%lu)\n", permission_msg.size());
    return false;
  }
  LOG_DEBUG("passcheck_read_result=%d", passcheck_read_result);
  constexpr size_t total_size_len = 2;
  constexpr size_t digest_len_len = 2;
  const uint16_t digest_len = ntohs(*(uint16_t *)permission_msg.data());
  constexpr size_t nonce_len_len = 2;
  const size_t nonce_offset = digest_len_len + digest_len;
  const auto last_permission_idx = permission_msg.size() - 1;
  if((nonce_offset + 1) > last_permission_idx) {
    LOG_INFO("invalid permission_message nonce_offset(%lu)>(%lu)\n", nonce_offset, last_permission_idx);
    return false;
  }
      
  const uint16_t nonce_len = ntohs(*(uint16_t *)(permission_msg.data() + nonce_offset));
  LOG_DEBUG("nonce_len=%d", nonce_len);
  size_t msg_id_offset = nonce_offset + nonce_len_len + nonce_len;
  if((msg_id_offset) > last_permission_idx) {
    LOG_INFO("invalid permission_message msg_id_offset(%lu)>(%lu)\n", msg_id_offset, last_permission_idx);
    return false;
  }

  const uint8_t msg_id = permission_msg[msg_id_offset];
  if(msg_id != 9)  {
    LOG_WARN("Expected permission message (%d)!=(9)", msg_id);
    return false;
  }
  constexpr size_t msg_id_len = 1;
  constexpr size_t timestamp_len = 4;
  size_t device_id_len_offset = msg_id_offset + msg_id_len + timestamp_len;
  if((device_id_len_offset) > last_permission_idx) {
    LOG_INFO("invalid permission_message device_id_len_offset(%lu)>(%lu)\n", device_id_len_offset, last_permission_idx);
    return false;
  }
  const uint8_t device_id_len = permission_msg[device_id_len_offset];

  const size_t admittance_offset = device_id_len_offset + device_id_len + 1;
  if(admittance_offset > last_permission_idx) {
    LOG_INFO("invalid permission_message admittance_offset(%lu)>(%lu)\n", admittance_offset, last_permission_idx);
    return false;
  }
  const uint8_t admittance = permission_msg[admittance_offset];
  constexpr uint8_t grant = 2; // 2 is granted
  const auto cause_offset = admittance_offset + 1;
  if(cause_offset > last_permission_idx) {
    LOG_INFO("invalid permission_message cause_offset(%lu)>(%lu)\n", cause_offset, last_permission_idx);
    return false;
  }
  
  const uint8_t cause = permission_msg[cause];
  if(admittance != grant) {
    LOG_ERROR("Not admitted (%d)!=(%d) cause=(%d)", admittance, grant, cause);
    return false;
  }
  LOG_INFO("Admitted (%d)==(%d) cause=(%d)", admittance, grant, cause);

  return true;
}



uint8_t ecall_process_client(int client,
                             uint8_t use_ssl,
                             uint8_t use_sediment) {
  std::unique_ptr<Sockets::ISocket> client_socket;
  if (use_ssl) {
    client_socket.reset(new Sockets::SSLSocket(client));
  } else {
    client_socket.reset(new Sockets::PlainSocket(client));
  }
                 
  LOG_DEBUG("[Accepted client client=%d]", client_socket->sock);
        
  const auto finish_accept_result = client_socket->finish_accept();
  LOG_INFO("[sock=%d finish_accept_result=%d]", client_socket->sock, finish_accept_result);
  if (finish_accept_result <= 0) {
    return -1;
  }

  // if (!options.skip_sediment) {
  if (use_sediment) {
    LOG_ERROR("[sock=%d SEDIMENT enabled]", client);
    if (!attest_sediment(*client_socket, use_ssl)) {
      LOG_ERROR("[sock=%d SEDIMENT attestation failed]", client);
      return -1;
    }
    LOG_INFO("[sock=%d SEDIMENT complete]", client);
  }
    
  BootStrapReturn bs_return = bootstrap_qjs();
  auto scopeCleanupQJS = std::unique_ptr<ScopeCleanupQJS>(new ScopeCleanupQJS(bs_return));

  // Handle SSL/TLS connections
  while(1) {
    // LOG_DEBUG("Start sleep");
    // sleep(10);
    // LOG_DEBUG("Finish sleep");
    std::string serial_buffer_str1 {};
    // const auto serial_buffer_len = RecvSizedBuffer(*client_socket, serial_buffer_str1, options, "serial");
    const auto serial_buffer_len = RecvSizedBuffer(*client_socket, serial_buffer_str1, "serial");
        
    LOG_TRACE("serial_buffer_str1.c_str()=%p", serial_buffer_str1.c_str());
    LOG_TRACE("serial_buffer_str1.size()=%lu", serial_buffer_str1.size());
    LOG_TRACE("serial_buffer_str1:  %d %d %d",
              serial_buffer_str1[0],
              serial_buffer_str1[1],
              serial_buffer_str1[2]);
    if (serial_buffer_len <=0) {
      return -1;
    }
    LOG_INFO("[Processing Client Request]");
    qjs_add_arguments(&bs_return, (char *)serial_buffer_str1.c_str(), serial_buffer_len);

    std::string buffer_str {};
    auto buffer_len = RecvSizedBuffer(*client_socket, buffer_str, "buffer");

    if (buffer_len <= 0) {
      return -1;
    }

    /* create the atlas execution command */
    std::string cbuffer {"globalThis.current_nonce = globalThis.current_nonce ||  0;\nglobalThis.msg="};
    // std::string cbuffer {"globalThis.msg=eval('("};
    const auto cbuffer_len = cbuffer.length() + buffer_len + 5;
    cbuffer.reserve(cbuffer_len);

    /* get the plain text */
    /* TODO(epl): Is it possible to decrypt in place? */
    std::string og;
    og = buffer_str;
    LOG_TRACE("[og.length()=%zu og=%s]", og.length(), og.c_str());
    LOG_DEBUG("[og.length()=%lu]", og.length());
    cbuffer.append(std::begin(og), std::end(og));

    LOG_TRACE("[cbuffer=%s]", cbuffer.c_str());
    LOG_DEBUG("[qjs_execute_code cbuffer Call]");
    qjs_execute_code(&bs_return, (char *)cbuffer.c_str(), cbuffer.length());
    LOG_DEBUG("[qjs_execute_code cbuffer Done]");

    // execute the request
    // SPDLOG_TRACE("qjs_execute_code call evaluator={}", (char *)evaluator);
    LOG_TRACE("[qjs_execute_code evaluator Call evaluator=%s]", (char *)evaluator);
    qjs_execute_code(&bs_return, (char *)evaluator, evaluator_len);
    LOG_DEBUG("[qjs_execute_code evaluator Done]");
    // if we are not running locally, send the results back to the client */
    std::string encrypted_response;
    const uint32_t serial_size = serial_response_.size();
    const auto r_serial_write_response_size =
      client_socket->write(&serial_size,
                           sizeof(serial_size));

    LOG_DEBUG("[sizeof=%lu r_serial_write_response_size=%lu]",
              sizeof(r_serial_write_response_size),
              (long int)r_serial_write_response_size);

    LOG_DEBUG("[fd=%d"
              " r_serial_write_response_size=%lu]",
              client_socket->sock,
              (long int)r_serial_write_response_size);

    if (r_serial_write_response_size <= 0) {
      LOG_ERROR("[fd=%d"
                " r_serial_write_response_size=%lu]",
                client_socket->sock,
                (long int)r_serial_write_response_size);
      return -1;
    }
    //    ssize_t r_serial_write_response = -1;

    const auto r_serial_write_response =
      client_socket->write((uint8_t *)serial_response_.c_str(),
                           serial_size);
    LOG_DEBUG("[fd=%d"
              " r_serial_write_response=%lu]",
              client_socket->sock,
              (long int)r_serial_write_response);

    if (r_serial_write_response <= 0){
      LOG_ERROR("[fd=%d"
                " r_serial_write_response=%lu]",
                client_socket->sock,
                (long int)r_serial_write_response);
      return -1;
    }

    LOG_DEBUG("Next");
  }
  return 0;
}

std::stack<int> accepted_sockets;

int SetupSSLContext(SSL_CTX &ssl_ctx,
                    const char *ssl_certificate,
                    const char *ssl_key) {

  LOG_DEBUG("OPENSSL Version = %s", SSLeay_version(SSLEAY_VERSION));
  if(!ssl_certificate || !ssl_key) {
    LOG_INFO("SSL: Generating cert and key->Start");
    EVP_PKEY *pkey = generatePrivateKey();
    X509 *x509 = generateCertificate(pkey);

    SSL_CTX_use_certificate(&ssl_ctx, x509);
    SSL_CTX_use_PrivateKey(&ssl_ctx, pkey);

    RSA *rsa=RSA_generate_key(512, RSA_F4, NULL, NULL);
    SSL_CTX_set_tmp_rsa(&ssl_ctx, rsa);
    RSA_free(rsa);

    SSL_CTX_set_verify(&ssl_ctx, SSL_VERIFY_NONE, 0);
    LOG_INFO("SSL: Generating cert and key->Done");
  }
  LOG_INFO("SSL: Using given cert and key->Start");

  BIO *cert_bio = BIO_new_mem_buf(ssl_certificate, -1);
  X509 *cert = PEM_read_bio_X509_AUX(cert_bio, NULL, NULL, NULL);
  SSL_CTX_use_certificate(&ssl_ctx, cert);
  X509_free(cert);
  cert = nullptr;
  BIO_free(cert_bio);
  cert_bio = nullptr;

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
  BIO_free(key_bio);
  
  if (NULL == pkey) {
    LOG_ERROR("SSL: r=%d PEM_read_bio_PrivateKey", r);
    //          ERR_print_errors_fp(stderr);
    return EXIT_FAILURE;
  }
  int ret = SSL_CTX_use_PrivateKey(&ssl_ctx, pkey);
  if (!ret) {
    LOG_ERROR("SSL: ret=%d PEM_read_bio_PrivateKey", ret);
    //          ERR_print_errors_fp(stderr);
    return EXIT_FAILURE;
  }
  EVP_PKEY_free(pkey);
  LOG_INFO("SSL: Using given cert and key->Done");
  return EXIT_SUCCESS;
}

uint8_t ecall_setup_ssl_context(const char *ssl_certificate,
                                const char *ssl_key) {

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

  return true;
}

uint8_t ecall_setup_sediment_context(const char *auth_key,
                                     const char *sediment_signing_key
                                     ) {
  sediment_signing_key_ = sediment_signing_key;

  const std::string authKeyStr {auth_key};
  for (auto it = std::begin(authKeyStr); it != std::end(authKeyStr); std::advance(it, 2)) {
    constexpr int base16 = 16;
    const auto hex_str = std::string(it, it + 2);
    authKey.push_back(stoul(hex_str, nullptr, base16));
  }
    
  return true;
}
