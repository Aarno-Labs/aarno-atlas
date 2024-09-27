#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>

#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>
#include <boost/scope_exit.hpp>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <iostream>
#include <thread>
#include <fstream>

#include <sys/time.h>

#define DEBUG_LOG 1
#define sgx_printf printf
#include "../utils/log/sgx_log.h"


using namespace boost;

extern const char *evaluator;
extern size_t evaluator_len;


extern thread_local std::string serial_response_;

extern "C" {
typedef struct JSRuntime JSRuntime;
typedef struct JSContext JSContext;

// quickjs context for each thread
typedef struct {
    JSContext *quickjs_enclave_ctx;
    JSRuntime *quickjs_enclave_rt;
} BootStrapReturn;

BootStrapReturn bootstrap_qjs() ;
void CleanupQJS(BootStrapReturn *bs_return);
void qjs_execute_code(BootStrapReturn *bs_return, char *buffer, int32_t len);
void qjs_add_arguments(BootStrapReturn *bs_return, char *serialized_args, int32_t len);
}

static auto create_socket_server(int port) {
    int s = 1;
    int optval = 1;
    struct sockaddr_in addr {
            .sin_family = AF_INET,
            .sin_port = htons(port),
            .sin_addr = {.s_addr = htonl(INADDR_ANY)}};

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        LOG_ERROR("sgx_socket");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) < 0) {
        LOG_ERROR("sgx_setsockopt");
        exit(EXIT_FAILURE);
    }
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("´sgx_bind");
        exit(EXIT_FAILURE);
    }
    if (listen(s, 128) < 0) {
        LOG_ERROR("sgx_listen");
        exit(EXIT_FAILURE);
    }
    return s;
}

extern time_t getTimestamp();

int aarno_close(int sock) {
  return close(sock);
}

SSL_CTX* create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_method();
    // method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}
void configure_server_context(SSL_CTX *ctx,
                              const std::string &cert_file,
                              const std::string &key_file)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_file.c_str()) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

uint8_t ecall_process_client(int client,
                             uint8_t use_ssl,
                             uint8_t use_sediment
                             );

uint8_t ecall_setup_ssl_context(const char *ssl_certificate,
                                const char *ssl_key);

uint8_t ecall_setup_sediment_context(const char *auth_key,
                                     const char *sediment_signing_key);

int main(int argc, char *argv[]) {
    program_options::options_description desc("Allowed options");

    desc.add_options()
            ("help,h", "produce help message")
            ("port,p", program_options::value<uint16_t>(), "plain text port")
            ("ssl,s",  program_options::value<uint16_t>(), "ssl port")
            ("cert,c", program_options::value<std::string>(), "ssl certifcate file")
            ("key,k",  program_options::value<std::string>(), "ssl key file")
            ("sed,d",  program_options::value<std::string>(), "sediment signing key")
            ("firewall,f",  program_options::value<std::string>(), "firewall server address as ip:port")
            ("ra-log-lvl,l",  program_options::value<uint32_t>(), "remote attestation log lvl")
            ("sediment,m",  "expect SEDIMENT passports")
            ("sed-auth-key,a",  program_options::value<std::string>(), "hex string of sediment authorization key")
            ("rpi,r",  program_options::value<std::string>(), "the rpi file");
    program_options::variables_map args;
    program_options::store(program_options::parse_command_line(argc, argv, desc), args);
    program_options::notify(args);

    if(args.contains("help") || args.size() == 0) {
        std::cout << desc << std::endl;
        exit(0);
    }

    const auto only_cert_or_key = args.contains("key") ^ args.contains("cert");
    if (only_cert_or_key) {
        LOG_ERROR("Must specify cert file and key file");
        LOG_ERROR("key = %s", args.contains("key") ? args["key"].as<std::string>().c_str() : "<null>");
        LOG_ERROR("cert = %s", args.contains("cert") ? args["cert"].as<std::string>().c_str() : "<null>");
        std::stringstream ss_error;
        desc.print(ss_error);
        LOG_ERROR("%s", ss_error.str().c_str());
    }

    bool use_sediment = false;
    if (args.contains("sediment")) {
      use_sediment = true;
      if (!args.contains("sed-auth-key")) {
        LOG_ERROR("Must specify sediment authorization key with sediment");
        std::cout << desc << std::endl;
        exit(1);
      }

      std::ifstream sediment_key_in(args["sed"].as<std::string>(),
                                    std::ios::in | std::ios::binary);
      if(!sediment_key_in) {
        LOG_ERROR("Sediment key file not found '%s'",
                  args["sed"].as<std::string>().c_str());
        std::cout << desc << std::endl;
        exit(1);
      }        
      
      std::string sediment_key_str = std::string{std::istreambuf_iterator<char>(sediment_key_in),
                                                 std::istreambuf_iterator<char>()};

      ecall_setup_sediment_context(args["sed-auth-key"].as<std::string>().c_str(),
                                   sediment_key_str.c_str());
      
      if(!args.contains("firewall")) {
        LOG_ERROR("Must specify firewall ip");
        std::cout << desc << std::endl;
        exit(1);
      }

      const std::string firewall_arg = args["firewall"].as<std::string>();
      std::vector<std::string> ip_port;
      boost::split(ip_port, firewall_arg, boost::is_any_of(":"));
      if(ip_port.size() != 2) {
        LOG_ERROR("Firewall endpoint invalid expected '127.0.0.0:8000' received '%s' ",
                  firewall_arg.c_str());
        exit(1);
      }

      auto test_port = atol(ip_port[1].c_str());
      if (test_port <= 0 || test_port > std::numeric_limits<uint16_t>::max()) {
        LOG_ERROR("Invalid firewall port %ld from %s", test_port, firewall_arg.c_str());
        exit(1);
      }
      uint16_t firewall_port = static_cast<uint16_t>(test_port);

    }
    
    // SSL throws SIGPIPE which kill process
    signal(SIGPIPE, SIG_IGN);
    // struct sigaction sig_ign {SIG_IGN};
    // sigaction(SIGPIPE, &sig_ign, NULL);
    
    struct sockaddr_in addr;
    unsigned int len = sizeof(addr);

    if (args.contains("ssl")) {
        int sock = create_socket_server(args["ssl"].as<uint16_t>());
        LOG_DEBUG("SSL accepting on sock=%d", sock);
        if (sock < 0) {
            LOG_ERROR("create_socket_client");
            return 1;
        }

        std::ifstream ssl_key_in(args["key"].as<std::string>(),
                                 std::ios::in | std::ios::binary);
        std::string ssl_key_str = std::string{std::istreambuf_iterator<char>(ssl_key_in),
                                        std::istreambuf_iterator<char>()};

        std::ifstream ssl_cert_in(args["cert"].as<std::string>(),
                                 std::ios::in | std::ios::binary);
        std::string ssl_cert_str = std::string{std::istreambuf_iterator<char>(ssl_cert_in),
                                        std::istreambuf_iterator<char>()};
        ecall_setup_ssl_context(ssl_cert_str.c_str(),
                                ssl_key_str.c_str());

        while (1) {
            LOG_INFO("Wait for new connections...");
            int client = accept(sock, (struct sockaddr *)&addr, &len);
            if (client < 0) {
                LOG_ERROR("Unable to accept");
                break;
            }
            const bool send_encrypted = true;
            std::thread conn(&ecall_process_client, client, send_encrypted, use_sediment);
            conn.detach();
        }
    }

    if (args.contains("port")) {
        int sock = create_socket_server(args["port"].as<uint16_t>());
        LOG_DEBUG("Clear accepting on sock=%d", sock);
        if (sock < 0) {
            LOG_ERROR("create_socket_client");
            return 1;
        }
        LOG_DEBUG("Wait for new connections...");
        while(1) {
            int client = accept(sock, (struct sockaddr *)&addr, &len);
            if (client < 0) {
                LOG_ERROR("Unable to accept");
                break;
            }
            const bool send_encrypted = false;
            std::thread conn(&ecall_process_client, client, send_encrypted, use_sediment);
            conn.detach();
        }
    }
}
