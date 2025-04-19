// threadpool.cpp

#include "threadpool.h"        // Include the header for function declarations 
#include <iostream>            // For debug output (optional)

// Constructor: initializes the thread pool and starts worker threads
ThreadPool::ThreadPool(size_t num_threads) : stop(false) {
    // Create the requested number of threads and add them to the vector
    for (size_t i = 0; i < num_threads; ++i) {
        threads.emplace_back([this]() {
            this->clients();  // Each thread runs the worker() method
        });
    }
}

// Destructor: tells threads to stop and joins them
ThreadPool::~ThreadPool() {
    stop = true;                       // Set the atomic stop flag to true

    condition.notify_all();           // Wake up all waiting threads

    // Wait for all threads to finish
    for (std::thread &thread : threads) {
        if (thread.joinable()) {
            thread.join();            // Cleanly close each thread
        }
    }
}

// Adds a client_fd (socket) to the task queue
void ThreadPool::enqueue(int client_fd) {
    {
        std::lock_guard<std::mutex> lock(queue_mutex);  // Lock the queue

        tasks.push(client_fd);                          // Add client socket to the queue
    }

    condition.notify_one();  // Notify one waiting worker that there is a new task
}

// Worker function that runs in each thread
void ThreadPool::clients() {
    while (true) {
        int client_fd;  // Placeholder for the task (client socket)

        {
            std::unique_lock<std::mutex> lock(queue_mutex);  // Lock access to the queue

            // Wait until there's a task or the pool is being stopped
            condition.wait(lock, [this]() {
                return !tasks.empty() || stop;  // Keep waiting unless there's a task or we're stopping
            });

            // If stop flag is set and no more tasks, exit the loop
            if (stop && tasks.empty()) {
                return;
            }

            client_fd = tasks.front();   // Get the next client socket
            tasks.pop();                 // Remove it from the queue
        }

        // Now handle the client outside the lock (so other threads can access the queue)
        handle_client(client_fd);  // This is my existing request handler
    }
}
