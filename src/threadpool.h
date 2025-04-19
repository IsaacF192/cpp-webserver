#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <functional>         // For std::function
#include <thread>             // For std::thread
#include <vector>             // For std::vector
#include <mutex>              // For std::mutex
#include <queue>              // For std::queue
#include <condition_variable> // For std::condition_variable
#include <atomic>             // For std::atomic

class ThreadPool {
public:
    ThreadPool(size_t num_threads);   // Constructor
    ~ThreadPool();                    // Destructor

    void enqueue(int client_fd);      // Add new client socket to the queue

private:
    void clients();                    // Function that each worker thread runs

    std::vector<std::thread> threads; // Vector of client threads
    std::queue<int> tasks;            // Queue of client connections (fd values)

    std::mutex queue_mutex;           // Mutex to protect access to task queue
    std::condition_variable condition; // Signals when a new task is available
    std::atomic<bool> stop;           // Tells threads when to shut down
};

#endif
