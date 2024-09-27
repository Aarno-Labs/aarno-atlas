cmake_minimum_required(VERSION 3.14)
  
project(simple VERSION 0.0.0 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)

# Enable ExternalProject support
include(ExternalProject)
include(FetchContent)

# set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
# set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")

FetchContent_Declare(
        spdlog
        GIT_REPOSITORY "https://github.com/gabime/spdlog.git"
        GIT_TAG "v1.12.0"
#        PREFIX "${EXTERNAL_DIR}/spdlog"
        UPDATE_COMMAND ""
        INSTALL_COMMAND ""
        TEST_COMMAND "")

FetchContent_MakeAvailable(spdlog)

set(BOOST_INCLUDE_LIBRARIES program_options asio scope_exit)
set(BOOST_ENABLE_CMAKE ON)

set(Boost_USE_MULTITHREADED ON)  
set(Boost_USE_STATIC_RUNTIME OFF) 
FetchContent_Declare(
  Boost
  GIT_REPOSITORY https://github.com/boostorg/boost.git
  GIT_TAG boost-1.83.0
)
FetchContent_MakeAvailable(Boost)
      


include_directories(${CMAKE_BINARY_DIR}/openssl/include)
link_directories(${CMAKE_BINARY_DIR}/openssl/lib)

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


add_definitions(-g -DPLATFORM_RPI -DSPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_DEBUG -DXD -DAARNO_SIMPLE -DCONFIG_BIGNUM -DCONFIG_VERSION=\"2023-09-06\")

include_directories(
  ${CMAKE_BINARY_DIR}/_deps/spdlog-src/include
  ${CMAKE_BINARY_DIR}/openssl/include
)

link_directories(${CMAKE_BINARY_DIR}/openssl/lib)
link_libraries(ssl crypto Boost::scope_exit Boost::algorithm Boost::program_options ${CMAKE_DL_LIBS} pthread)

set(SIMPLE_SERVER simple-server)

file(GLOB ENCLAVE_SRC
  ${CMAKE_SOURCE_DIR}/../Enclave/isolated/*.c
)

add_definitions("-DBOOST_ALLOW_DEPRECATED_HEADERS")
add_executable(${SIMPLE_SERVER}
  ProcessClient.cpp
  simple.cpp
  ${ENCLAVE_SRC}
  )

# add_executable(passport_check
#     sediment.cpp)

add_dependencies(${SIMPLE_SERVER} spdlog OpenSSL)


