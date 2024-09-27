cmake_minimum_required(VERSION 3.14)

project(qjs VERSION 0.0.0 LANGUAGES C ASM CXX)

add_definitions(-D_GNU_SOURCE -DSEDIMENT -DPLATFORM_RPI -DXD -DAARNO_SIMPLE -DCONFIG_BIGNUM -DCONFIG_VERSION=\"2023-09-06\")

# 
# add_definitions(-DENABLE_LOGGING)
# set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
# set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")

# add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../ra ${CMAKE_BINARY_DIR}/ra)

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


include_directories(${OPENSSL_DIR}/include)
include_directories(${MBEDTLS_DIR}/include)
link_directories(${MBEDTLS_DIR}/lib ${OPENSSL_DIR}/lib ${OPENSSL_DIR}/lib)

set(QJS_LIB_SRC
     ${CMAKE_CURRENT_SOURCE_DIR}/quickjs.c
     ${CMAKE_CURRENT_SOURCE_DIR}/libregexp.c
     ${CMAKE_CURRENT_SOURCE_DIR}/libunicode.c
     ${CMAKE_CURRENT_SOURCE_DIR}/cutils.c
     ${CMAKE_CURRENT_SOURCE_DIR}/quickjs-libc.c
     ${CMAKE_CURRENT_SOURCE_DIR}/tweetnacl.c
     ${CMAKE_CURRENT_SOURCE_DIR}/libbf.c
)


##########################################################
# Use this if you need to regenerate repl.c and qjscalc.c
# This _will_ run qjsc which means this must a native build
# add_executable(qjsc
#   ${CMAKE_CURRENT_SOURCE_DIR}/qjsc.c
#   ${QJS_LIB_SRC}
#   )

# add_dependencies(qjsc MbedTLS OpenSSL)
# add_custom_command(
#   OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/repl.c
#   COMMAND qjsc -c -o ${CMAKE_CURRENT_SOURCE_DIR}/repl.c -m ${CMAKE_CURRENT_SOURCE_DIR}/repl.js
#   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/repl.js qjsc
#   )

# add_custom_target(repl_c DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/repl.c)

# add_custom_command(
#   OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/qjscalc.c
#   COMMAND qjsc -c -o ${CMAKE_CURRENT_SOURCE_DIR}/qjscalc.c -m ${CMAKE_CURRENT_SOURCE_DIR}/qjscalc.js
#   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/qjscalc.js qjsc
#   )

# add_custom_target(qjscalc_c DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/qjscalc.c)

# SET_SOURCE_FILES_PROPERTIES(${CMAKE_CURRENT_SOURCE_DIR}/qjscalc.c PROPERTIES GENERATED TRUE)
# SET_SOURCE_FILES_PROPERTIES(${CMAKE_CURRENT_SOURCE_DIR}/repl.c PROPERTIES GENERATED TRUE)
##########################################################

add_executable(qjs
  ${CMAKE_CURRENT_SOURCE_DIR}/qjs.c
  ${QJS_LIB_SRC}
  ${CMAKE_CURRENT_SOURCE_DIR}/qjscalc.c
  ${CMAKE_CURRENT_SOURCE_DIR}/repl.c    
  )


file(GLOB SEDIMENT_SRCS
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  ../../ra/modules/protocol/*.cpp
  ../../ra/apps/common/*.cpp
  ../../ra/servers/common/EndpointSock.cpp
  ../../ra/apps/rpi/RPIProver.cpp
  ../../ra/apps/rpi/BoardRPI.cpp
)
add_library(sediment
  ${SEDIMENT_SRCS}
  )
target_include_directories(sediment PUBLIC ../../ra/modules/protocol ../../ra/servers/common ../../ra/apps/common)
target_compile_features(sediment PRIVATE cxx_std_17)


add_dependencies(qjs OpenSSL MbedTLS sediment)
add_dependencies(sediment OpenSSL MbedTLS)

target_link_directories(qjs PUBLIC ${CMAKE_BINARY_DIR}/ra)
target_link_libraries(qjs PUBLIC
  sediment
  mbedcrypto
  mbedx509
  stdc++fs
  stdc++
  ssl
  crypto
  m
  ${CMAKE_DL_LIBS}
  pthread)

# add_dependencies(qjs protocol rpi MbedTLS OpenSSL )
#add_dependencies(qjs protocol rpi )
##########################################################
# Use this if you need to regenerate repl.c and qjscalc.c
# add_dependencies(qjs qjsc)
##########################################################


