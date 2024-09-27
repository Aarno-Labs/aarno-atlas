#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <mutex>


#include "EndpointSock.hpp"


class SSLEndpointSock : virtual public EndpointSock {
public:
  SSLEndpointSock(SSL_CTX *ssl_ctx, SSL* ssl, Endpoint ep, int sock) :
    EndpointSock(ep, sock),
    ssl_ctx(ssl_ctx),
    ssl(ssl) {
    // ssl_mutex_.lock();
  }

  virtual ~SSLEndpointSock() = default;

  //  virtual int recv_data(int peer_sock, char *ptr, int avail) {return 0;}
  virtual int recv_data(int peer_sock, char *ptr, int avail) {
    //    std::lock_guard<std::mutex> ssl_lock{this->ssl_mutex_};
    SD_LOG(LOG_DEBUG, "[%s:%d][%d] SSLEndpointSock recv_data peer_sock=%d avail=%d", __FILE__, __LINE__, pthread_self(), peer_sock, avail);

    auto result = SSL_read(ssl, ptr, avail);
    // while(true) {
    //   if (result == 0) {
    //     SD_LOG(LOG_INFO, "[%s:%d][%d] SSLEndpointSock1 zero recv error0 peer_sock=%d result=%d error=%d error_string=%s state_string=%s", __FILE__, __LINE__, pthread_self(), peer_sock, result, SSL_get_error(ssl, result), ERR_error_string(ERR_get_error(), NULL), SSL_state_string(ssl));
    //     SD_LOG(LOG_INFO, "[%s:%d][%d] SSLEndpointSock recv zero error peer_sock=%d errno=%s", __FILE__, __LINE__, pthread_self(), peer_sock, strerror(errno));
    //     //        sleep(1);
    //     result = SSL_read(ssl, ptr, avail);
    //     continue;
    //   }
    //   break;
        
    // }
    SD_LOG(LOG_DEBUG, "[%s:%d][%d] SSLEndpointSock1 recv peer_sock=%d result=%d", __FILE__, __LINE__, pthread_self(), peer_sock, result);
    if (result <=0) {
        SD_LOG(LOG_DEBUG, "[%s:%d][%d] SSLEndpointSock recv error peer_sock=%d result=%d error=%d error_string=%s state_string=%s", __FILE__, __LINE__, pthread_self(), peer_sock, result, SSL_get_error(ssl, result), ERR_error_string(ERR_get_error(), NULL), SSL_state_string(ssl));
        SD_LOG(LOG_DEBUG, "[%s:%d][%d] SSLEndpointSock recv error peer_sock=%d errno=%s", __FILE__, __LINE__, pthread_self(), peer_sock, strerror(errno));
      

      ERR_print_errors_fp(stderr);
      return -1;
    }
    return result;
  }

  virtual int send_data(int peer_sock, const char *ptr, int avail, const char *where) {
    // std::lock_guard<std::mutex> ssl_lock{this->ssl_mutex_};
    SD_LOG(LOG_DEBUG, "[%s:%d][%d] SSLEndpointSock send_data peer_sock=%d avail=%d", __FILE__, __LINE__, pthread_self(), peer_sock, avail);

    const auto result = SSL_write(ssl, ptr, avail);
    SD_LOG(LOG_DEBUG, "[%s:%d][%d] SSLEndpointSock sent where=%s peer_sock=%d result=%d", __FILE__, __LINE__, pthread_self(), where, peer_sock, result);
    if (result <=0) {
        SD_LOG(LOG_DEBUG, "[%s:%d][%d] SSLEndpointSock1 send error peer_sock=%d result=%d error=%d error_string=%s state_string=%s", __FILE__, __LINE__, pthread_self(), peer_sock, result, SSL_get_error(ssl, result), ERR_error_string(ERR_get_error(), NULL), SSL_state_string(ssl));
        // SD_LOG(LOG_INFO, "[%s:%d][%d] SSLEndpointSock send error peer_sock=%d errno=%s", pthread_self(), peer_sock, strerror(errno));
      ERR_print_errors_fp(stderr);
      return -1;
    }
    return result;
  }

  virtual void cleanup() {
    // std::lock_guard<std::mutex> ssl_lock{this->ssl_mutex_};
    
    SD_LOG(LOG_DEBUG, "[%s:%d] SSLEndpointSock shutdown peer_sock=%d result=%d", __FILE__, __LINE__, this->sock);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    ssl = nullptr;
    ssl_ctx = nullptr;
    // ssl_mutex_.unlock();
  }


  
private:
  SSL_CTX *ssl_ctx;
  SSL     *ssl;
  
};

