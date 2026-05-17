#include "worker_pool.h"

namespace hype {

WorkerPool::WorkerPool(unsigned n) {
    if (n == 0) n = std::thread::hardware_concurrency();
    if (n == 0) n = 4;

    for (unsigned i = 0; i < n; ++i) {
        workers_.emplace_back([this]() {
            while (true) {
                std::function<void()> task;
                {
                    std::unique_lock lk(mtx_);
                    cv_.wait(lk, [&] { return stop_ || !queue_.empty(); });
                    if (stop_ && queue_.empty()) return;
                    task = std::move(queue_.front());
                    queue_.pop();
                }
                task();
                if (--pending_ == 0)
                    idle_cv_.notify_all();
            }
        });
    }
}

WorkerPool::~WorkerPool() {
    {
        std::lock_guard lk(mtx_);
        stop_ = true;
    }
    cv_.notify_all();
    for (auto& w : workers_)
        if (w.joinable()) w.join();
}

void WorkerPool::wait_idle() {
    std::unique_lock lk(mtx_);
    idle_cv_.wait(lk, [&] { return pending_ == 0; });
}

}
