#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <stdio.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "sgx_tcrypto.h"
#include "funcs.h"
#define ENCLAVE_FILE "enclave.signed.so"
#define STDC_WANT_LIB_EXT1 1
#include "../Enclave/dh/tools.h"
#include "../Enclave/dh/tweetnacl.h"
#include <errno.h>
#include <locale.h>
#include <dlfcn.h>
#include <time.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include "nw.h"
#include <sys/socket.h>
#include <sys/param.h>
#define _unused(x) ((void)(x))


#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <iostream>
#include <fstream>
#include <streambuf>
#include <string>
#include <cerrno>
#include <thread>

#include "log/app_log.h"

#include "wqueue.h"

//double sgx_time = 0.0f;
double e2e_time = 0.0f;
double exec_time = 0.0f;
struct timespec te2e_start = {0, 0}, te2e_stop = {0, 0}, tsgx_start{0, 0}, tsgx_stop{0, 0}, 
                texec_start{0, 0}, texec_stop{0, 0};

void
ocall_print(uint8_t* value)
{
    int i;
    for(i = 0; i < 32; i++){
        printf("%2.2x", value[i]);
    }
}

long 
get_file_size(FILE *f)
{
  long size;
  fseek(f, 0, SEEK_END);
  size = ftell(f);
  fseek(f, 0, SEEK_SET);
  return size;
}

static int create_socket_server(int port)
{
  int s, optval = 1;
  struct sockaddr_in addr;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    LOG_ERROR("socket");
    exit(EXIT_FAILURE);
  }
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int)) < 0) {
    LOG_ERROR("setsockopt");
    exit(EXIT_FAILURE);
  }
  if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    LOG_ERROR("bind");
    exit(EXIT_FAILURE);
  }
  if (listen(s, 128) < 0) {
    LOG_ERROR("listen");
    exit(EXIT_FAILURE);
  }
  return s;
}

static void cleanup_openssl()
{
  EVP_cleanup();
}


// void GetClient(wqueue<int> &worker_queue,
//                sgx_enclave_id_t eid,
//                bool send_unencrypted,
//                bool use_ssl) {
//   const int sock = worker_queue.remove();
//   uint8_t pclient_result = 0;
//   ecall_process_client(eid, &pclient_result, sock, send_unencrypted, use_ssl);
// }

void GetClient(wqueue<int> *worker_queue,
               sgx_enclave_id_t eid,
               bool use_ssl,
               bool use_sediment) {
  const int sock = worker_queue->remove();
  uint8_t pclient_result = 0;
  ecall_process_client(eid, &pclient_result, sock, use_ssl, use_sediment);
}


typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/**
 * Print command line usage to stdout
 *
 * @param argv argv passed to main
 */
void usage(char **argv) {
    std::cout << "Usage: " << argv[0];
    std::cout << "  -h  Print this help message" << std::endl;
    std::cout << "  -p  <port>"
                 " port to listen for client connections";
    std::cout << " [-k <ssl_key_file> -c <ssl_certificate_file>]"
                 " file for ssl key and certificate" << std::endl;
    std::cout << "  -u  send bytes unencrypted" << std::endl;
    std::cout << " [-f <sediment cert file>"
                 " file sediment signing" << std::endl;
}



/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_MEMORY_MAP_FAILURE,
        "Failed to reserve memory for the enclave.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}


int
main(int argc, char *argv[])
{
    int32_t updated;
    sgx_enclave_id_t eid;
    int port;
    char opt;
    sgx_status_t ret;
    sgx_launch_token_t token = {0};
    ret = SGX_SUCCESS;
    eid = 0;
    port = 0;
    (void) ret;
#ifdef DEBUG
    /* create the enclave */
    printf("Creating Enclave\n");
#endif
    /*
     * Get arguments
     */
    char *ssl_certificate_file = nullptr;  // file name of ssl certificate
    char *ssl_key_file = nullptr;  // file name of ssl key
    char *sediment_key_file = nullptr; // location of sediment signing key
    char *sediment_auth_key_str = nullptr; // sediment authorization key as hex str
    bool ssl = false;
    bool send_unencrypted = false;
    while ((opt = getopt(argc, argv, "sc:k:p:h:f:a:u")) != -1) { 
        switch (opt) {
            case 'p':
                port = (short unsigned int)atoi(optarg);
                break;
            case 'c':
                ssl_certificate_file = optarg;
                break;
            case 'k':
                ssl_key_file = optarg;
                break;
            case 's':
                ssl = true;
                break;
            case 'u':
                send_unencrypted = true;
                break;
            case 'f':
                sediment_key_file = optarg;
                break;
            case 'a':
                sediment_auth_key_str = optarg;
                break;
            case 'h':
            default:
                usage(argv);
        }
    }

    // create the enclave
    ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token,
            &updated, &eid, NULL);
    if (ret != SGX_SUCCESS){
        LOG_ERROR("Failed to create enclave, code=%#x", ret);
        return 1;
    }
    /* init the enclave args */
    ret = ecall_init(eid, stdin, stdout, stdout);
    if (ret != SGX_SUCCESS){
        LOG_ERROR("Failed to init enclave, code=%#x", ret);
        return 1;
    }

    // Read certificate and key off file system outside of Enclave, then pass them
    // in a strings
    const bool one_ssl_is_null = (nullptr == ssl_key_file || nullptr == ssl_certificate_file);
    const bool both_ssl_null = (nullptr == ssl_key_file && nullptr == ssl_certificate_file);
    if (one_ssl_is_null && !both_ssl_null) {
      printf("%s:%d\n", __FILE__, __LINE__);
      LOG_ERROR("ssl_key_file(%s) and ssl_certificate_file(%s) must both be set or both null",
                ssl_key_file ? ssl_key_file : "<null>",
                ssl_certificate_file ? ssl_certificate_file : "<null>");
      return 1;
    }

    if(send_unencrypted && !both_ssl_null) {
      printf("%s:%d\n", __FILE__, __LINE__);
      LOG_ERROR("if unencrypted both ssl_key_file(%s) and ssl_certificate_file(%s) must be null",
                ssl_key_file ? ssl_key_file : "<null>",
                ssl_certificate_file ? ssl_certificate_file : "<null>");
      return 1;
    }

    if(send_unencrypted && ssl) {
      printf("%s:%d\n", __FILE__, __LINE__);
      LOG_ERROR("unencrypted and ssl options are mutually exclusive");
      return 1;
    }

    std::ifstream ssl_certificate_in;
    if(ssl_certificate_file) {
      ssl_certificate_in = std::ifstream{ssl_certificate_file, std::ios::in | std::ios::binary};
      if(!ssl_certificate_in) {
        LOG_ERROR("failed to open ssl_certificate_in_file=%s", ssl_certificate_file);
        perror(ssl_certificate_file);
        return 1;
      }
    }
    const std::string ssl_certificate_str =
      ssl_certificate_in ? std::string({std::istreambuf_iterator<char>(ssl_certificate_in),
                                        std::istreambuf_iterator<char>()}) : "";
      
    std::ifstream ssl_key_in(ssl_key_file, std::ios::in | std::ios::binary);
    if(ssl_key_file) {
      ssl_key_in = std::ifstream {ssl_key_file, std::ios::in | std::ios::binary};
      if(!ssl_key_in) {
        LOG_ERROR("failed to open ssl_key_file=%s", ssl_key_file);
        perror(ssl_key_file);
        return 1;
      }
    }
    std::string ssl_key_str =
      ssl_key_in ? std::string{std::istreambuf_iterator<char>(ssl_key_in),
                               std::istreambuf_iterator<char>()} : "";

    std::ifstream sediment_key_in(sediment_key_file, std::ios::in | std::ios::binary);
    if(sediment_key_file) {
      sediment_key_in = std::ifstream {sediment_key_file, std::ios::in | std::ios::binary};
      if(!sediment_key_in) {
        LOG_ERROR("failed to open sediment_key_file=%s", sediment_key_file);
        perror(sediment_key_file);
        return 1;
      }
    }
    std::string sediment_key_str =
      sediment_key_in ? std::string{std::istreambuf_iterator<char>(sediment_key_in),
                               std::istreambuf_iterator<char>()} : "";

    // For some reason SIGPIPE is escaping, so need to explicitly ignore IGN
    signal(SIGPIPE, SIG_IGN);

    if (sediment_auth_key_str != nullptr) {
      uint8_t sediment_setup = false;
      ecall_setup_sediment_context(eid, &sediment_setup, sediment_auth_key_str);

      if(!sediment_setup) {
        LOG_ERROR("[sediment setup failed]");
        return 1;
      }
    }

    if(ssl) {
      uint8_t ssl_setup = false;
      ecall_setup_ssl_context(eid, &ssl_setup,
                              ssl_certificate_str.c_str(),
                              ssl_key_str.c_str(),
                              sediment_key_str.c_str());
      if(!ssl_setup) {
        LOG_ERROR("Setup SSL Context failed (%d)", ssl_setup);
        return 1;
      }
    }

    struct sockaddr_in addr;
    unsigned int len = sizeof(addr);
    const int sock = create_socket_server(port);
    if (-1 == sock) {
      return 1;
    }


    wqueue<int> worker_queue;
    const auto use_sediment = sediment_key_file != nullptr;
    std::thread thread1(GetClient, &worker_queue, eid, ssl, use_sediment);
    std::thread thread2(GetClient, &worker_queue, eid, ssl, use_sediment);
    
    while (1) {
      LOG_DEBUG("Wait for new connections...");
      int client = accept(sock, (struct sockaddr *) &addr, &len);
      LOG_DEBUG("Got new connection [client=%d]", client);
      if (client < 0) {
        LOG_ERROR("Unable to accept");
        break;
      }
      worker_queue.add(client);
      LOG_DEBUG("Added connection [client=%d]", client);
    
      // bootstrap_qjs();
      // ProcessClient(client, send_unencrypted, use_ssl, *ssl_ctx.get());
      // sgx_close(client);
    }
    // sgx_close(sock);
    cleanup_openssl();
    

    thread1.join();
    thread2.join();
    

    // we should never go here
    sgx_destroy_enclave(eid);
}
