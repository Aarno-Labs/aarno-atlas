/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#pragma once

#include <memory>
#include "StateMachine.hpp"
#include "Seec.hpp"
#include "Device.hpp"
#include "DeviceManager.hpp"
#include "CommandLine.hpp"
#include "EndpointSock.hpp"
#include "ICalAuthToken.hpp"

using namespace std;

class Server : public StateMachine, public ICalAuthToken
{
protected:
    string sediment_home;
    string dbName;
    string dbType;

    std::unique_ptr<DeviceManager> deviceManager;

    void runProcedure(std::unique_ptr<EndpointSock>);

  // void finalizeAndSend(int peer_sock, Message *message);
    virtual void calAuthToken(Message *message, uint8_t *serialized, uint32_t len);
    virtual void setTimestamp(Message *message);

    virtual Device * authenticate(DeviceManager &deviceManager, Message *message, uint8_t *serialized, uint32_t len);
    virtual time_t getTimestamp();
    virtual void handlePubData(char *data);

    virtual Message * decodeMessage(uint8_t dataArray[], uint32_t len)
    {
        (void) dataArray;
        (void) len;

        return NULL;
    }

    virtual Message * handleMessage(DeviceManager &deviceManager, Message *message, EndpointSock &src, Device *device,
      uint8_t *serialized,
      uint32_t len)
    {
        (void) deviceManager;
        (void) message;
        (void) src;
        (void) device;
        (void) serialized;
        (void) len;

        return NULL;
    }

public:
    Server(Config &config, Board *board, CommandLine &cli)
      : StateMachine(config, board, cli.enable_ssl, cli.ssl_key_file, cli.ssl_cert_file),
        sediment_home(cli.getSedimentHome()),
        dbName(cli.getDatabase()),
        dbType(cli.getDatabaseType())
    { }

    virtual ~Server(){ }

    Seec * findSeec(DeviceManager &deviceManager, string deviceID);

    const string& getSedimentHome() const
    {
        return sediment_home;
    }

    void run();
};
