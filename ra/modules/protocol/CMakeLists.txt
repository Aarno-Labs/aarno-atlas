file(GLOB CPP_SOURCES
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.cpp
  ../../servers/common/EndpointSock.cpp
)

set(TARGET protocol)


add_library(${TARGET}
  ${CPP_SOURCES}
)
target_include_directories(protocol PRIVATE ${APPS_COMMON}
  ${OPENSSL_ROOT_DIR}/include
  ${MBEDTLS_ROOT_DIR}/include
  ${PAHO_MQTT_C_ROOT_DIR}/include
  ${PAHO_MQTT_CPP_ROOT_DIR}/include)
