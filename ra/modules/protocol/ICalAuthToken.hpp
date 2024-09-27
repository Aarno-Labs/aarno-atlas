#include <cstdint>
#include "Message.hpp"

#pragma once

class ICalAuthToken {
public:
  virtual void calAuthToken(Message *message, uint8_t *serialized, uint32_t len) = 0;
};
