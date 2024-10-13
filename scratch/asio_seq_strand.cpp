#include <asio.hpp>
#include <coroutine>
#include <queue>
#include <functional>
#include <iostream>
#include <optional>

/**
 * SequentialStrand class ensuring sequential execution of coroutines.
 * This means that the next coroutine will not start until the previous one has completed.
 * 
 * Important: It assumes a single-threaded ASIO executor.
 */
template <typename Executor>
class SequentialStrand
{
    asio::strand<Executor> strand_;
    std::queue<asio::awaitable<void>> tasks_;
    bool active_;
    bool stopping_;
    std::optional<asio::steady_timer> stop_timer_;

public:
    explicit SequentialStrand(const Executor& ex) //
        : strand_(asio::make_strand(ex)), active_(false), stopping_(false)
    {
    }

    size_t pending_tasks() const
    {
        return tasks_.size();
    }

    template <typename Awaitable>
    void post(Awaitable awaitable)
    {
        if (stopping_)
            return;

        tasks_.push(std::move(awaitable));
        if (!active_)
            schedule_next();
    }

    asio::awaitable<void> stop(bool cancel_enqueued)
    {
        return stop(asio::steady_timer::clock_type::duration::max(), cancel_enqueued);
    }

    template <typename Timeout>
    asio::awaitable<void> stop(Timeout timeout, bool cancel_enqueued)
    {
        stopping_ = true;
        if (!active_ && tasks_.empty())
            co_return;

        if (cancel_enqueued)
        {
            std::cout << "SequentialStrand: Dropping " << tasks_.size() << " enqueued tasks." << std::endl;

            // clear enqueued, not-yet scheduled tasks
            while (!tasks_.empty())
                tasks_.pop();
        }

        // use a timer to signal when to stop
        auto executor = co_await asio::this_coro::executor;
        stop_timer_.emplace(executor, timeout);
        asio::error_code ec2;
        co_await stop_timer_->async_wait(asio::redirect_error(asio::use_awaitable, ec2));
    }

private:
    void schedule_next()
    {
        if (tasks_.empty())
        {
            active_ = false;
            if (stopping_ && stop_timer_)
            {
                stop_timer_->cancel();
                stop_timer_.reset();
            }
            return;
        }

        active_ = true;
        auto next_task = std::move(tasks_.front());
        tasks_.pop();

        asio::co_spawn(
            strand_,
            [this, task = std::move(next_task)]() mutable -> asio::awaitable<void>
            {
                try
                {
                    co_await std::move(task);
                }
                catch (const std::exception& e)
                {
                    std::cerr << "Coroutine exception: " << e.what() << std::endl;
                }
                catch (...)
                {
                    std::cerr << "Coroutine unknown exception" << std::endl;
                }

                // Schedule the next coroutine
                schedule_next();

                co_return;
            },
            asio::detached
        );
    }
};

// Example usage
asio::awaitable<void> example_coroutine(int id)
{
    std::cout << "Coroutine " << id << " start\n";
    co_await asio::steady_timer(co_await asio::this_coro::executor, std::chrono::seconds(1))
        .async_wait(asio::use_awaitable);
    std::cout << "Coroutine " << id << " end\n";
}

asio::awaitable<void> main_coroutine()
{
    auto executor = co_await asio::this_coro::executor;

    SequentialStrand strand(executor);

    strand.post(example_coroutine(1));
    strand.post(example_coroutine(2));
    strand.post(example_coroutine(3));

    // // Wait for a bit before stopping
    // co_await asio::steady_timer(executor, std::chrono::seconds(1)).async_wait(asio::use_awaitable);

    std::cout << "Stopping strand..." << std::endl;
    co_await strand.stop(true);
    std::cout << "Strand stopped." << std::endl;

    // This coroutine will not be executed
    strand.post(example_coroutine(4));
}

int main()
{
    asio::io_context io_context;
    asio::co_spawn(io_context, main_coroutine(), asio::detached);
    io_context.run();
    return 0;
}


// #include <asio.hpp>
// #include <asio/experimental/awaitable_operators.hpp>
// #include <coroutine>
// #include <queue>
// #include <functional>
// #include <iostream>

// // The SequentialStrand class ensuring sequential execution
// class SequentialStrand
// {
//     asio::strand<asio::io_context::executor_type> strand_;
//     std::queue<std::shared_ptr<asio::awaitable<void>>> tasks_;

// public:
//     explicit SequentialStrand(asio::io_context& ioc) : strand_(asio::make_strand(ioc))
//     {
//     }

//     template <typename Awaitable>
//     void post(Awaitable awaitable)
//     {
//         auto task_ptr = std::make_shared<asio::awaitable<void>>(std::move(awaitable));
//         tasks_.push(task_ptr);
//         if (tasks_.size() == 1)
//         {
//             schedule_next();
//         }
//     }

// private:
//     void schedule_next()
//     {
//         if (tasks_.empty())
//             return;
//         auto next_task = tasks_.front();

//         asio::co_spawn(
//             strand_,
//             [this, task = std::move(next_task)]() mutable -> asio::awaitable<void>
//             {
//                 try
//                 {
//                     co_await std::move(*task);
//                 }
//                 catch (const std::exception& e)
//                 {
//                     // Handle exception (e.g., log it)
//                     std::cerr << "Coroutine exception: " << e.what() << std::endl;
//                 }
//                 catch (...)
//                 {
//                     // Handle other exceptions
//                     std::cerr << "Coroutine unknown exception" << std::endl;
//                 }
//                 tasks_.pop();
//                 if (!tasks_.empty())
//                 {
//                     schedule_next();
//                 }
//                 co_return;
//             },
//             asio::detached
//         );
//     }
// };

// // Example usage
// asio::awaitable<void> example_coroutine(int id, int sleep_ms)
// {
//     std::cout << "Coroutine " << id << " start\n";

//     // Simulate asynchronous work
//     co_await asio::steady_timer(
//         co_await asio::this_coro::executor, std::chrono::milliseconds(sleep_ms)
//     )
//         .async_wait(asio::use_awaitable);

//     std::cout << "Coroutine " << id << " end\n";
// }

// int main()
// {
//     asio::io_context io_context;
//     SequentialStrand strand(io_context);

//     strand.post(example_coroutine(1, 1000));
//     strand.post(example_coroutine(2, 200));
//     strand.post(example_coroutine(3, 50));

//     io_context.run();
//     return 0;
// }