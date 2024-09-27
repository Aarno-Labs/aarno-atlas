#include <thread>
#include <mutex>
#include <condition_variable>
#include <list>
#include "log/app_log.h"
      

/*
using namespace std;

template <typename T> class wqueue
{
    list<T>   m_queue;
    pthread_mutex_t m_mutex;
    pthread_cond_t  m_condv;

public:
    wqueue() {
        pthread_mutex_init(&m_mutex, NULL);
        pthread_cond_init(&m_condv, NULL);
    }
    ~wqueue() {
        pthread_mutex_destroy(&m_mutex);
        pthread_cond_destroy(&m_condv);
    }
    void add(T item) {
        pthread_mutex_lock(&m_mutex);
        m_queue.push_back(item);
        pthread_cond_signal(&m_condv);
        pthread_mutex_unlock(&m_mutex);
    }
    T remove() {
        pthread_mutex_lock(&m_mutex);
        while (m_queue.size() == 0) {
            pthread_cond_wait(&m_condv, &m_mutex);
        }
        T item = m_queue.front();
        m_queue.pop_front();
        pthread_mutex_unlock(&m_mutex);
        return item;
    }
    int size() {
        pthread_mutex_lock(&m_mutex);
        int size = m_queue.size();
        pthread_mutex_unlock(&m_mutex);
        return size;
    }
};
*/


template <typename T> class wqueue
{
  std::list<T>   m_queue;
  std::condition_variable m_condv;
  std::mutex      m_mutex;

public:
    void add(T item) {
      LOG_DEBUG("Enter add");
      //      std::unique_lock<std::mutex> guard(m_mutex);
      std::lock_guard<std::mutex> guard(m_mutex);
      LOG_DEBUG("Add mutex");
      m_queue.push_back(item);
      LOG_DEBUG("Add push");
      m_condv.notify_one();
      LOG_DEBUG("Add done1");
    }
    T remove() {
      LOG_DEBUG("Enter remove");
      std::unique_lock<std::mutex> guard(m_mutex);
      LOG_DEBUG("queue check size");
      m_condv.wait(guard, [this]{return this->m_queue.size() != 0;});
      // while (m_queue.size() == 0) {
      //   m_condv.wait(guard, []{return true;});
      // }
      T item = m_queue.front();
      m_queue.pop_front();
      return item;
    }
    int size() {
      std::unique_lock<std::mutex> lock(m_mutex);
      int size = m_queue.size();
      return size;
    }
};
