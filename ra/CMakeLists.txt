# Copyright (c) 2023-2024 Peraton Labs
# SPDX-License-Identifier: Apache-2.0
# Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).

cmake_minimum_required(VERSION 3.14)

# set(CMAKE_CXX_COMPILER g++)
# set(CMAKE_C_COMPILER gcc)
set(RPI_BUILD true)

project(sediment VERSION 0.0.0 LANGUAGES C CXX ASM)

set(ARC ${CMAKE_SYSTEM_PROCESSOR})
set(LIB "lib/${ARC}")

option(SPDLOG_ENABLED "SPDLOG Enabled" ON)
option(MYSQL_ENABLED "MySQL Enabled" OFF)

if(NOT WIN32)
  string(ASCII 27 Esc)
  set(ColourReset "${Esc}[m")
  set(BoldGreen   "${Esc}[1;32m")
endif()

include(${CMAKE_CURRENT_SOURCE_DIR}/version.cmake)

add_compile_definitions(PLATFORM_RPI=1)

### COMMON
set(PROTOCOL      modules/protocol)
set(MQTT          modules/mqtt)

set(SVR_COMMON    servers/common)

include_directories(${PROTOCOL})
include_directories(${MQTT})
include_directories(${PROVER} PRIVATE data)
include_directories(include)
include_directories(modules)
include_directories(${SVR_COMMON})
include_directories(${CMAKE_CURRENT_BINARY_DIR}/generated)

include_directories(${CMAKE_BINARY_DIR}/openssl/include)
include_directories(${CMAKE_BINARY_DIR}/mbedtls/include)

link_directories(${CMAKE_BINARY_DIR}/openssl/lib)
link_directories(${CMAKE_BINARY_DIR}/mbedtls/lib)

include(ExternalProject)

##################################
### MBEDTLS
set(MBEDTLS_DIR "${CMAKE_BINARY_DIR}/mbedtls")
ExternalProject_Add(
        MbedTLS
        GIT_REPOSITORY "https://github.com/Mbed-TLS/mbedtls.git"
        GIT_TAG "v3.4.1"
        SOURCE_DIR              "${CMAKE_BINARY_DIR}/src/mbedtls-src"
        BINARY_DIR              "${CMAKE_BINARY_DIR}/build/mbedtls-build"
        INSTALL_DIR             ${MBEDTLS_DIR}
        UPDATE_COMMAND          ""
        CONFIGURE_COMMAND       ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE} -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> <SOURCE_DIR>
        )
##################################

set(SSL_CONFIG "./config")

if(DEFINED CMAKE_TOOLCHAIN_FILE)
  set(FULL_SSL --cross-compile-prefix=${CMAKE_C_COMPILER})
  string(REPLACE "gcc" "" SSL_CROSS_PREFIX ${FULL_SSL})
  set(LINUX_GENERIC32 linux-generic32)
  set(SSL_CONFIG "./Configure")
endif()

message("SSL_CROSS_PREFIX=${SSL_CROSS_PREFIX}")

##################################
### OPENSSL
set(OPENSSL_DIR ${CMAKE_BINARY_DIR}/openssl)
ExternalProject_Add(
        OpenSSL
        GIT_REPOSITORY "https://github.com/openssl/openssl.git"
        GIT_TAG "OpenSSL_1_1_1d"
        SOURCE_DIR              "${CMAKE_BINARY_DIR}/src/openssl-src"
        INSTALL_DIR             "${CMAKE_BINARY_DIR}/openssl"
        BUILD_IN_SOURCE true
        UPDATE_COMMAND          ""
        CONFIGURE_COMMAND ${SSL_CONFIG} --prefix=${OPENSSL_DIR} ${SSL_CROSS_PREFIX} shared ${LINUX_GENERIC32}
        BUILD_COMMAND make -j 8
        INSTALL_COMMAND make install_sw
        )
##################################



link_libraries(
  mbedtls
  mbedcrypto
  mbedx509  
)

### PROVER
#set(PROVER      prover)
set(APPS_COMMON apps/common)
set(RPI         apps/rpi)

file(GLOB PROVER_SRC
  ${RPI}/*.cpp
  ${APPS_COMMON}/*.cpp
  ${SVR_COMMON}/*.cpp
  servers/verifier/ConfigAttest.cpp
  
)

# add_executable(${PROVER}
#   ${PROVER_SRC}
# )

# target_include_directories(${PROVER} PRIVATE ${APPS_COMMON})
# target_link_libraries(${PROVER} PRIVATE
#   protocol
#   dl
#   pthread
# )

### SERVER
set(server_libs
    sqlite3
    protocol
    ssl
    crypto
    pthread
)


### VERIFIER
set(SVR_VERIFIER  servers/verifier)
set(VERIFIER verifier)

file(GLOB VERIFIER_SRC
  ${SVR_VERIFIER}/*.cpp
  ${SVR_COMMON}/*.cpp
)

add_executable(${VERIFIER}
  ${VERIFIER_SRC}
)

target_link_libraries(${VERIFIER} PRIVATE
  ${server_libs}
)

### FIREWALL
set(FIREWALL firewall)
set(SVR_FIREWALL  servers/firewall)

file(GLOB FIREWALL_SRC
  ${SVR_FIREWALL}/*.cpp
  ${SVR_COMMON}/*.cpp
)

add_executable(${FIREWALL}
  ${FIREWALL_SRC}
)

target_link_libraries(${FIREWALL} PRIVATE
  ${server_libs}
)

##########

# set_target_properties(${PROVER}
#     PROPERTIES
#     ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
#     LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
#     RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
#     )

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -g -Wall -Wextra")
# target_link_options(${PROVER} PRIVATE "-Wl,--gc-sections")

# if(DEFINED CLANG_FLAGS)
#   compile_options(${PROVER} PUBLIC ${CLANG_FLAGS})
# endif()

# if(DEFINED UBUNTU_AFTER_2017)
#   compile_options(${PROVER} PUBLIC ${UBUNTU_AFTER_2017})
# endif()
#add_subdirectory(apps/rpi/udf)
add_subdirectory(modules/protocol)


##################################
### librpi.a
set(RPI         apps/rpi)

add_library(rpi
  ${RPI}/RPIProver.cpp
  ${RPI}/BoardRPI.cpp
  ${APPS_COMMON}/Prover.cpp
  ${SVR_COMMON}/CommandLine.cpp
  servers/verifier/ConfigAttest.cpp
  )


add_dependencies(protocol MbedTLS OpenSSL)
add_dependencies(rpi protocol MbedTLS OpenSSL)


##################################
