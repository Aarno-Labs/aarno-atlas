/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#include "sediment.h"

#include "StateMachine.hpp"
#include "Log.hpp"
#include "SSLEndpointSock.hpp"

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

using namespace std;

bool StateMachine::sendMessage(EndpointSock &eps, MessageID messageID, uint8_t *serialized, uint32_t msg_len, const char *where)
{
    if (serialized == NULL) {
        SD_LOG(LOG_ERR, "failed to serialize message");
        return false;
    }
    // if (config.getTransport() == TRANSPORT_SEDIMENT_MQTT &&
    //   messageID == DATA)
    // {
    //     string pub = Log::toHexNoLimit((char *) serialized, msg_len);
    //     mqtt.publish((char *) &pub[0]);
    // }
    // else {
    int sent     = 0;
    int remain   = msg_len;
    uint8_t *ptr = serialized;
    while (remain > 0) {
      // int bytes = send(eps.getSock(), (const char *) ptr, remain, MSG_NOSIGNAL);
      const int bytes = eps.send_data(eps.getSock(), (const char *)ptr, remain, where);
      // if (bytes == EPIPE) {
      if (bytes <= EPIPE) {
        SD_LOG(LOG_ERR, "broken send pipe: %s", Log::toMessageID(messageID).c_str());
        return false;
      }
      ptr    += bytes;
      sent   += bytes;
      remain -= bytes;
    }
    // }
    return true;
}

void StateMachine::finalizeAndSend(EndpointSock &eps, Message *message,
                                   ICalAuthToken &calAuthToken,
                                   const char *where)
{
    setTimestamp(message);
    AuthToken &authToken = message->getAuthToken();

    uint32_t msg_len;
    uint8_t *serialized = message->serialize(&msg_len);

    calAuthToken.calAuthToken(message, serialized, msg_len);

    uint32_t size = authToken.getSize();
    Vector data(size);
    authToken.encode(data);

    memcpy(serialized + AUTH_TOKEN_OFFSET, (char *) data.at(0), authToken.getSize());

    sendMessage(eps, message->getId(), serialized, msg_len, where);
    free(serialized);

    SD_LOG(LOG_DEBUG, "[%s:%d %s()]sent [size=%d msg_len=(%d)..eps=[%s].......msg=%s]",
           __FILE__, __LINE__, __FUNCTION__,
           size, msg_len, eps.toStringOneline().c_str(), message->toString().c_str());
}

bool StateMachine::isWellFormed(uint8_t dataArray[], uint32_t len)
{
    if (len < MIN_MSG_LEN) {
        SD_LOG(LOG_ERR, "message too short: %d, minimum length %d", len, MIN_MSG_LEN);
        return false;
    }

    if (len > MAX_MSG_LEN) {
        SD_LOG(LOG_ERR, "message too long: %d, max length %d", len, MAX_MSG_LEN);
        return false;
    }

    MessageID id = (MessageID) dataArray[MESSAGE_ID_OFFSET];
    if (id <= MIN_MSG_ID || id >= MAX_MSG_ID) {
        SD_LOG(LOG_ERR, "invalid message id: %d", id);
        return false;
    }

    return true;
}

EndpointSock *StateMachine::FinishClientConnection(int sock, const Endpoint &ep) {
  SD_LOG(LOG_DEBUG, "[%s:%d][%d] FinishClientConnection", __FILE__, __LINE__, pthread_self());
  if(!this->enable_ssl_) {
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


// std::mutex SSLEndpointSock::ssl_mutex_;
EndpointSock *StateMachine::FinishServerAccept(int client_sock, const Endpoint &ep) {
  SD_LOG(LOG_DEBUG, "[%s:%d][%d] FinishServerConnection", __FILE__, __LINE__, pthread_self());
  //  std::lock_guard<std::mutex> ssl_lock{SSLEndpointSock::ssl_mutex_};
  if(!this->enable_ssl_) {
    SD_LOG(LOG_DEBUG, "[%s:%d][%d] using plain server client_socket=%d", __FILE__, __LINE__, client_sock);
    return new EndpointSock(ep, client_sock);
  }
  
  if(!ssl_initialized_server) {
    const SSL_METHOD *method = TLS_server_method();
    ssl_ctx_server = SSL_CTX_new(method);
    if (ssl_ctx_server == NULL) {
      SD_LOG(LOG_ERR, "client_sock=%d", client_sock);
      perror("Unable to create SSL context");
      ERR_print_errors_fp(stderr);
    }

    /* Set the key and cert */
    SD_LOG(LOG_DEBUG, "[%s:%d][%d] FinishServerConnection ssl_cert_file=%s",
           __FILE__, __LINE__, pthread_self(),
           ssl_cert_file.c_str());
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx_server, ssl_cert_file.c_str()) <= 0) {
      SD_LOG(LOG_ERR, "client_sock=%d", client_sock);
      perror("cert chain");
      ERR_print_errors_fp(stderr);
    }
  
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx_server, ssl_key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
      SD_LOG(LOG_ERR, "client_sock=%d", client_sock);
      perror("private key");
      ERR_print_errors_fp(stderr);
    }
    ssl_initialized_server = true;
  }

  SSL *ssl = SSL_new(ssl_ctx_server);
  SSL_set_fd(ssl, client_sock);

  if (SSL_accept(ssl) <= 0) {
      SD_LOG(LOG_ERR, "client_sock=%d", client_sock);
    perror("accept");
    ERR_print_errors_fp(stderr);
  }
  
  SD_LOG(LOG_DEBUG, "[%s:%d][%d] FinishServerConnection done", __FILE__, __LINE__, pthread_self());
  return new SSLEndpointSock{ssl_ctx_server, ssl, ep, client_sock};
 }

