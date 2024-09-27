#include <math.h>
#include <memory>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "../../apps/common/Prover.hpp"
#include "BoardRPI.hpp"
#include "CommandLine.hpp"
#include "Log.hpp"
#include "Comm.hpp"
#include "CryptoServer.hpp"
#include "SSLEndpointSock.hpp"


using SSL_CTX_PTR = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
SSL_CTX_PTR ssl_ctx {nullptr, &SSL_CTX_free};


bool ssl_initialized_client = false;
SSL_CTX *ssl_ctx_client = nullptr;

EndpointSock *FinishClientConnection(int sock, bool enable_ssl, const Endpoint &ep, const std::string &ssl_cert_file) {
  SD_LOG(LOG_DEBUG, "[%s:%d][%d] FinishClientConnection", __FILE__, __LINE__, pthread_self());
  if(!enable_ssl) {
    SD_LOG(LOG_DEBUG, "[%s:%d][%d] using plain client sock=%d", __FILE__, __LINE__, sock);
    return new EndpointSock(ep, sock);
  }
  //  std::lock_guard<std::mutex> ssl_lock{SSLEndpointSock::ssl_mutex_};
  if(!ssl_initialized_client) {
    const SSL_METHOD *method = TLS_client_method();
    ssl_ctx_client = SSL_CTX_new(method);
    if (ssl_ctx_client == NULL) {
      perror("Unable to create SSL context");
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
    }

    SD_LOG(LOG_DEBUG, "[%s:%d][%d] FinishClientConnection ssl_cert_file=%s",
           __FILE__, __LINE__, pthread_self(),
           ssl_cert_file.c_str());
    SSL_CTX_set_verify(ssl_ctx_client, SSL_VERIFY_PEER, NULL);
    if (!SSL_CTX_load_verify_locations(ssl_ctx_client, ssl_cert_file.c_str(), NULL)) {
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
    }
    ssl_initialized_client = true;
  }

  SSL *ssl = SSL_new(ssl_ctx_client);
  SSL_set_fd(ssl, sock);
  /* Set host name for SNI */
  SD_LOG(LOG_DEBUG, "[%s:%d] %s %s", __FILE__, __LINE__, __FUNCTION__, ep.getAddress().c_str());
  SSL_set_tlsext_host_name(ssl, ep.getAddress().c_str());
  /* Configure server hostname check */
  SSL_set1_host(ssl, ep.getAddress().c_str());

  if (SSL_connect(ssl) != 1) {
    printf("SSL connection to server failed\n\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return new SSLEndpointSock{ssl_ctx_client, ssl, ep, sock};
 }


auto RecvSizedBuffer(int sock,
                     EndpointSock &socket,
                     std::string &buffer_str,
                     const char msg[]) -> int {
  uint16_t msg_buffer_len = 0;
  const auto read_buf_len = socket.recv_data(sock,
                                             (char *)&msg_buffer_len,
                                             sizeof(msg_buffer_len));
  uint16_t buffer_len_with_size = ntohs(msg_buffer_len);
  SD_LOG(LOG_DEBUG,"[%s]"
            " fd=%d"
            " read_buf_len=%u"
            " buffer_len_with_size=%u"
            " msg_buffer_len=%u",
            msg,
            sock,
            read_buf_len,
            buffer_len_with_size,
            msg_buffer_len);

  if(read_buf_len <= 0){
    SD_LOG(LOG_ERR,"[%s]"
              " fd=%d"
              " read_buf_len=%u",
              msg,
              sock,
              read_buf_len);
    return -1;
  }

  if(buffer_len_with_size < 2) {
    SD_LOG(LOG_ERR, "[%s]  buffer_len_with_size=%u<2", buffer_len_with_size);
    return -1;
  }

  const uint16_t buffer_len = buffer_len_with_size;

  buffer_str.resize(buffer_len * sizeof(unsigned char));
  auto *buffer = (char *)&buffer_str.data()[0];
  memcpy(buffer, &buffer_len, sizeof(buffer_len));
  
  uint32_t total_read = 2; // subtract the 2 for the total size already read

  while (total_read < buffer_len) {
    SD_LOG(LOG_DEBUG,"[%s] fd=%d total_read=%u buffer_len=%u",
              msg,
              sock,
              total_read,
              buffer_len);
    const auto read_buf =
      socket.recv_data(sock,
                       buffer + total_read,
                       buffer_len - total_read);
    SD_LOG(LOG_DEBUG,"[%s]"
              " fd=%d"
              " read_buf=%d",
              msg,
              sock,
              read_buf);

    if(read_buf <= 0){
      SD_LOG(LOG_INFO, "[%s]"
               " fd=%d"
               " read_buf=%d",
               msg,
               sock,
               read_buf);
      return -1;
    }
    total_read += read_buf;
  }
  SD_LOG(LOG_DEBUG,"[%s][done] fd=%d total_read=%u buffer_len=%u",
            msg, sock, total_read, buffer_len);
  return total_read;

}
static int create_socket_client(const char *ip, uint32_t port) 
{
  int sockfd;
  struct sockaddr_in dest_addr;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd < 0) {
    SD_LOG(LOG_ERR, "socket failed");
    return -1;
  }

  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
  dest_addr.sin_addr.s_addr = (long)inet_addr(ip);
  memset(&(dest_addr.sin_zero), '\0', 8);

  SD_LOG(LOG_DEBUG, "Connecting %s:%d...", ip, port);
  if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) == -1) {
    SD_LOG(LOG_ERR, "Cannot connect");
    return -1;
  }

  return sockfd;
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


static uint8_t *FinalizeMessage(Message &message,
                                const time_t timestamp,
                                Crypto &crypto,
                                uint32_t &msg_len) {
    message.setTimestamp(timestamp);
    uint8_t *serialized = message.serialize(&msg_len);

    AuthToken &authToken = message.getAuthToken();
    crypto.calDigest(authToken, serialized, msg_len, message.getPayloadOffset());

    uint32_t size = authToken.getSize();
    Vector data(size);
    authToken.encode(data);

    memcpy(serialized + AUTH_TOKEN_OFFSET, (char *) data.at(0), authToken.getSize());

    return serialized;
}


extern "C" {
  typedef struct {
    uint8_t *passport;
    size_t passport_size;
    const char *device_id;
  } PassportBytes;
  
  int ProverRun(PassportBytes *passport_bytes,
                 const char config_file[],
                 const char exe[],
                 const int enable_ssl,
                 const char ssl_cert_file[],
                 const char ssl_key_file[],
                 const int ra_log_level) {
    Log::setConsoleLoglevel(ra_log_level);
    Log::setLoglevel(ra_log_level);
    
    Config config(NV_PROVER);
    config.parseFile(config_file);
    BoardRPI board {(char *)exe};
    board.setId(config.getComponent().getID());
    board.setConfigFile(config_file);

    auto attestSqn = board.getAttestSqn();
    // Prover prover(config, &board,
    //               static_cast<bool>(enable_ssl),
    //               ssl_cert_file,
    //               ssl_key_file);
    // prover.attestSqn = attestSqn;
    auto prover_component = config.getComponent();
    const auto prover_endpoint = prover_component.getOutgoing();
    const auto prover_address = prover_endpoint->getAddress();
    const auto prover_port = prover_endpoint->getPort();
    SD_LOG(LOG_INFO, "connect to %s:%d", prover_address.c_str(), prover_port );
    Crypto crypto;
    crypto.changeKey(KEY_AUTH, config.getAuthKey().data(), config.getAuthKey().size());
    crypto.changeKey(KEY_ATTESTATION, config.getAttestKey().data(), config.getAttestKey().size());
    crypto.changeKey(KEY_ENCRYPTION, config.getEncKey().data(), config.getEncKey().size());
    
    {
      const auto msg_timestamp = getTimestamp();
      ConfigMessage config_msg{};
      config_msg.setDeviceID(config.getComponent().getID());
      uint32_t config_msg_size = 0;
      auto config_msg_bytes =
        std::unique_ptr<uint8_t, decltype(std::free) *>(
                                                        FinalizeMessage(config_msg,
                                                                        msg_timestamp,
                                                                        crypto,
                                                                        // crypto,
                                                                        config_msg_size),
                                                        std::free);
      int config_sock = create_socket_client(prover_address.c_str(), prover_port);
      if(-1 == config_sock) {
        return -1;
      }
    SD_LOG(LOG_INFO, "prover to %s:%d", prover_address.c_str(), prover_port );
      std::unique_ptr<EndpointSock> config_socket {
        FinishClientConnection(config_sock, enable_ssl, *prover_endpoint, "cert.pem")
          };
      const auto config_send =
        config_socket->send_data(config_sock,
                                 (char *)config_msg_bytes.get(),
                                 config_msg_size,
                                 "send_config");

      if(config_send == -1) {
        SD_LOG(LOG_ERR, "config send failed config_send=%d", config_send);
        return -1;
      }

      std::string config_receive_bytes;
      const auto config_receive_result = RecvSizedBuffer(config_sock,
                                                         *config_socket,
                                                         config_receive_bytes,
                                                         "config");

      if(config_receive_result == -1) {
        SD_LOG(LOG_ERR, "config receive failed config_receive_result=%d", config_receive_result);
        return -1;
      }

      Vector config_dummy_vec{
        (uint8_t *)config_receive_bytes.c_str(),
          static_cast<int>(config_receive_bytes.size())};
      Message dummy {};
      dummy.decode(config_dummy_vec);
    }
      
    Endpoint attest_ep;
    {
      const auto msg_timestamp = getTimestamp();
      PassportRequest pass_req_msg{};
      pass_req_msg.setDeviceID(config.getComponent().getID());
      pass_req_msg.setReason(INIT);
      uint32_t pass_req_msg_size = 0;
      auto pass_req_msg_bytes =
        std::unique_ptr<uint8_t, decltype(std::free) *>(
                                                        FinalizeMessage(pass_req_msg,
                                                                        msg_timestamp,
                                                                        crypto,
                                                                        pass_req_msg_size),
                                                        std::free);
      int pass_req_sock = create_socket_client(prover_address.c_str(), prover_port);
      if(-1 == pass_req_sock) {
        return -1;
      }
    SD_LOG(LOG_INFO, "pass to %s:%d", prover_address.c_str(), prover_port );
      std::unique_ptr<EndpointSock> pass_req_socket {
        FinishClientConnection(pass_req_sock, enable_ssl, *prover_endpoint, "cert.pem")
      };
    SD_LOG(LOG_INFO, "pass done %s:%d", prover_address.c_str(), prover_port );

      
      const auto pass_req_send =
        pass_req_socket->send_data(pass_req_sock,
                                   (char *)pass_req_msg_bytes.get(),
                                   pass_req_msg_size,
                                   "pass_req_send");

      if(pass_req_send == -1) {
        SD_LOG(LOG_ERR, "passport request failed pass_req_send=%d", pass_req_send);
        return -1;
      }

      std::string pass_req_receive_bytes;
      const auto pass_req_receive_result =
        RecvSizedBuffer(pass_req_sock,
                        *pass_req_socket,
                        pass_req_receive_bytes,
                        "passport_request");

      if(pass_req_receive_result == -1) {
        SD_LOG(LOG_ERR, "passport request receive failed pass_req_receive_result=%d", pass_req_receive_result);
        return -1;
      }

      Vector pass_resp_vec{
        (uint8_t *)pass_req_receive_bytes.c_str(),
          static_cast<int>(pass_req_receive_bytes.size())};
      PassportResponse pass_resp {};
      pass_resp.decode(pass_resp_vec);
      SD_LOG(LOG_INFO, "copy to %s:%d", prover_address.c_str(), prover_port );
      attest_ep.copy(pass_resp.getEndpoint());
      board.setBaseTime(pass_resp.getTimestamp());
    }

    {
      const auto msg_timestamp = getTimestamp();
      AttestationRequest attest_req_msg{};
      attest_req_msg.setDeviceID(config.getComponent().getID());
      constexpr int RA_PORT = 8999;
      attest_req_msg.setPort(RA_PORT);
      attestSqn++;
      // prover.attestSqn = attestSqn;
      board.saveAttestSqn(attestSqn);
      attest_req_msg.setCounter(attestSqn);
        
      uint32_t attest_req_msg_size = 0;
      auto attest_req_msg_bytes =
        std::unique_ptr<uint8_t, decltype(std::free) *>(
                                                        FinalizeMessage(attest_req_msg,
                                                                        msg_timestamp,
                                                                        crypto,
                                                                        attest_req_msg_size),
                                                        std::free);
      int attest_req_sock = create_socket_client(attest_ep.getAddress().c_str(), attest_ep.getPort());
      if(-1 == attest_req_sock) {
        return -1;
      }
      SD_LOG(LOG_INFO, "attest_req_socket %s:%d", prover_address.c_str(), prover_port );
      
      std::unique_ptr<EndpointSock> attest_req_socket {
        FinishClientConnection(attest_req_sock, enable_ssl, attest_ep, "cert.pem")
      };
      const auto attest_req_send =
        attest_req_socket->send_data(attest_req_sock,
                                   (char *)attest_req_msg_bytes.get(),
                                   attest_req_msg_size,
                                   "attest_req_send");
      if(attest_req_send == -1) {
        SD_LOG(LOG_ERR, "attestation request failed attest_req_send=%d", attest_req_send);
        return -1;
      }

      std::string attest_req_receive_bytes;
      const auto attest_req_receive_result =
        RecvSizedBuffer(attest_req_sock,
                        *attest_req_socket,
                        attest_req_receive_bytes,
                        "attest");

      if(attest_req_receive_result == -1) {
        SD_LOG(LOG_ERR, "attest receive failed attest_req_receive_result=%d", attest_req_receive_result);
        return -1;
      }

      Vector chall_resp_vec{
        (uint8_t *)attest_req_receive_bytes.c_str(),
          static_cast<int>(attest_req_receive_bytes.size())};
      Challenge chall_resp {};
      chall_resp.decode(chall_resp_vec);
      board.saveAttestSqn(attestSqn);

        Seec seec {config};
        seec.setCrypto(&crypto);
        std::string sediment_home = ""; // TODO(epl): fix
        
        std::unique_ptr<Message> evidence {
             Prover::prepareEvidence(&chall_resp,
                                     attestSqn,
                                     config.getComponent().getID(),
                                     board,
                                     sediment_home,
                                     seec)};

      uint32_t evidence_req_msg_size = 0;
      auto evidence_req_msg_bytes =
        std::unique_ptr<uint8_t, decltype(std::free) *>(
                                                        FinalizeMessage(*evidence,
                                                                        msg_timestamp,
                                                                        crypto,
                                                                        evidence_req_msg_size),
                                                        std::free);
      const auto evidence_send =
        attest_req_socket->send_data(attest_req_sock,
                                   (char *)evidence_req_msg_bytes.get(),
                                   evidence_req_msg_size,
                                   "evidence_req_send");

      if(evidence_send == -1) {
        SD_LOG(LOG_ERR, "evidence request failed evidence_send=%d", evidence_send);
        return -1;
      }

      std::string grant_receive_bytes;
      const auto grant_receive_result =
        RecvSizedBuffer(attest_req_sock,
                        *attest_req_socket,
                        grant_receive_bytes,
                        "grant");
      
      if(grant_receive_result == -1) {
        SD_LOG(LOG_ERR, "grant receive failed grant_req_receive_result=%d", grant_receive_result);
        return -1;
      }

      Vector grant_vec{
        (uint8_t *)grant_receive_bytes.c_str(),
          static_cast<int>(grant_receive_bytes.size())};
      Grant grant{};
      grant.decode(grant_vec);
      auto passport = grant.getPassport();
      Vector encode_vec {static_cast<int>(passport.getSize())};
      passport.encode(encode_vec);
      passport_bytes->passport_size = encode_vec.size();
    
      passport_bytes->passport = (uint8_t *)malloc(passport_bytes->passport_size);
      memcpy(passport_bytes->passport, encode_vec.at(0), passport_bytes->passport_size);
      passport_bytes->device_id = strdup(config.getComponent().getID().c_str());
    }
    return 0;
  }
}
