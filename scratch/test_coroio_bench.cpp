#include <signal.h>
#include <thread>
#include <x86intrin.h>

#include "coroio/all.hpp"

using NNet::TAddress;
using NNet::TDefaultPoller;
using NNet::TValueTask;
using NNet::TSocket;
using TLoop = NNet::TLoop<TDefaultPoller>;

struct payload
{
    uint64_t ts_clt_sent = 0;
    uint64_t ts_srv = 0;
    uint64_t ts_clt_recv = 0;
    // char arr[1024];

    inline double client_latency() const
    {
        return (static_cast<double>(ts_srv - ts_clt_sent) / 3.2) / 1000;
    }

    inline double server_latency() const
    {
        return (static_cast<double>(ts_clt_recv - ts_srv) / 3.2) / 1000;
    }

    inline double rtt_latency() const
    {
        return (static_cast<double>(ts_clt_recv - ts_clt_sent) / 3.2) / 1000;
    }
};

TValueTask<void> client_handler(TSocket socket, TLoop* loop)
{
    payload p;
    ssize_t size = 0;

    (void)loop;

    std::cout << "Adding client\n";
    try
    {
        while ((size = co_await socket.ReadSome(&p, sizeof(payload))) > 0)
        {
            p.ts_srv = __rdtsc();
            co_await socket.WriteSome(&p, sizeof(payload));
        }
    }
    catch (const std::exception& ex)
    {
        std::cerr << "Exception: " << ex.what() << "\n";
    }
    if (size == 0)
    {
        std::cerr << "Client disconnected\n";
    }
    co_return;
}

TValueTask<void> server(TLoop* loop)
{
    TSocket socket(TAddress{"127.0.0.1", 8888}, loop->Poller());
    socket.Bind();
    socket.Listen();

    try
    {
        while (true)
        {
            auto client = co_await socket.Accept();
            client_handler(std::move(client), loop);
        }
    }
    catch (const std::exception& ex)
    {
        std::cout << "Exception: " << ex.what() << "\n";
    }
    co_return;
}

TValueTask<void> client(TLoop* loop, int clientId)
{
    ssize_t size = 0;

    int counter = 0;
    payload p;
    double avg_clt_srv = 0;
    double avg_srv_clt = 0;
    double avg_rtt = 0;

    try
    {
        TSocket socket(TAddress{"127.0.0.1", 8888}, loop->Poller());
        co_await socket.Connect();

        auto t = std::chrono::high_resolution_clock::now();
        do
        {
            ++counter;

            p.ts_clt_sent = __rdtsc();

            size = co_await socket.WriteSome(&p, sizeof(payload));
            size = co_await socket.ReadSome(&p, sizeof(payload));

            p.ts_clt_recv = __rdtsc();

            avg_clt_srv += p.client_latency();
            avg_srv_clt += p.server_latency();
            avg_rtt += p.rtt_latency();

            auto t2 = std::chrono::high_resolution_clock::now();

            // std::this_thread::sleep_for(std::chrono::seconds(1));

            if (std::chrono::duration_cast<std::chrono::seconds>(t2 - t).count() > 1)
            {
                avg_clt_srv /= counter;
                avg_srv_clt /= counter;
                avg_rtt /= counter;

                std::cerr << "#" << clientId << " " << counter << " msg/s  RTT " << avg_rtt
                          << " us   clt-srv latency " << avg_clt_srv << "   srv-clt latency "
                          << avg_srv_clt << " \n";
                t = t2;
                counter = 0;
                avg_clt_srv = 0;
                avg_srv_clt = 0;
                avg_rtt = 0;
            }

            // co_await loop->Poller().Sleep(std::chrono::milliseconds(1000));
        } while (size > 0);
    }
    catch (const std::exception& ex)
    {
        std::cout << "Exception: " << ex.what() << "\n";
    }
    co_return;
}

int main()
{
    signal(SIGPIPE, SIG_IGN);

    TLoop loop;
    int clients = 1;

    server(&loop);
    for (int i = 0; i < clients; i++)
    {
        client(&loop, i + 1);
    }

    loop.Loop();
    return 0;
}
