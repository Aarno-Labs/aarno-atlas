/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#pragma once
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// #include "../mqtt/Mqtt.hpp"
#include "Config.hpp"
#include "Board.hpp"
#include "Message.hpp"
#include "CommandLine.hpp"
#include "EndpointSock.hpp"
#include "ICalAuthToken.hpp"

using namespace std;

enum Procedure {
    PROC_INIT       = 0,
    PROC_ATTEST     = 1,
    PROC_JOIN       = 2,
    PROC_REPORT     = 3,
    PROC_KEY_CHANGE = 4,
};

class StateMachine
{
private:
  bool ssl_initialized_server = false;
  SSL_CTX *ssl_ctx_server = nullptr;
  bool ssl_initialized_client = false;
  SSL_CTX *ssl_ctx_client = nullptr;

  
protected:
    static const int MAX_TIME_OUT = 3; // # of consecutive message time outs
    Config &config;

    MessageID waitForMessage = MIN_MSG_ID;
    Endpoint endpoint;
    Board *board; // host of device specific functions
  // Mqtt mqtt;

    const bool enable_ssl_;
    const std::string ssl_key_file;
    const std::string ssl_cert_file;

    virtual Message * decodeMessage(uint8_t dataArray[], uint32_t len)
    {
        (void) dataArray;
        (void) len;
        return NULL;
    }

  //    virtual void calAuthToken(Message *message, uint8_t *serialized, uint32_t len) = 0;
    virtual void setTimestamp(Message *message) = 0;

public:
  StateMachine(Config &config,
               Board *board,
               bool enable_ssl,
               std::string ssl_key_file,
               std::string ssl_cert_file) :
        config(config),
        board(board),
        enable_ssl_(enable_ssl),
        ssl_key_file(ssl_key_file),
        ssl_cert_file(ssl_cert_file)
        
    {
        board->setId(config.getComponent().getID());
        signal(SIGPIPE, SIG_IGN);
    }

    virtual ~StateMachine()
    { }

  virtual void finalizeAndSend(EndpointSock &eps,
                               Message *message,
                               ICalAuthToken &calAuthToken,
                               const char *where);
  virtual bool sendMessage(EndpointSock &eps, MessageID messageID, uint8_t *serialized, uint32_t msg_len, const char *where);
    EndpointSock *FinishClientConnection(int sock, const Endpoint &ep);
    EndpointSock *FinishServerAccept(int sock, const Endpoint &ep);

    const Endpoint& getEndpoint() const
    {
        return endpoint;
    }

    bool isWellFormed(uint8_t dataArray[], uint32_t len);

    virtual void handlePubData(char *data) = 0;
    virtual void mqttConnect(){ }
};
