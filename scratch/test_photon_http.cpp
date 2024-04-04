#include <photon/photon.h>
#include <photon/thread/std-compat.h>

int main() {
    int ret = photon::init(photon::INIT_EVENT_DEFAULT, photon::INIT_IO_NONE);
    if (ret != 0) {
        return -1;
    }
    DEFER(photon::fini());

    // ...
}

// #include <coroio/all.hpp>

// #include <iostream>
// #include <signal.h>
// #include <string>

// using namespace NNet;
// using Loop = NNet::TLoop<TDefaultPoller>;
// using std::string;

// TValueTask<ssize_t> read_some(TSocket& socket)
// {
//     char buf[1024];
//     ssize_t size = co_await socket.ReadSome(buf, sizeof(buf));
//     std::cout << "Received: " << size << " bytes\n";
//     std::cout << string(buf, size) << "\n";
//     co_return size;
// }

// TValueTask<void> client(Loop* loop)
// {
//     ssize_t size = 0;
//     string hostname = "httpbin.org";
//     TAddress address;

//     try
//     {
//         TResolver<TPollerBase> resolver(loop->Poller());
//         auto addrs = co_await resolver.Resolve(hostname, EDNSType::DEFAULT);
//         std::cout << "'" << hostname << "': ";
//         for (auto& a : addrs)
//         {
//             std::cout << "Resolved hostname " << hostname << ": " << a.ToString() << ", ";
//         }

//         address = addrs.front();
//         address.WithPort(80);
//     }
//     catch (const std::exception& ex)
//     {
//         std::cout << "'" << hostname << "': ";
//         std::cout << ex.what();
//     }
//     std::cout << "\n";

//     co_return;

//     try
//     {
//         // https://httpbin.org/get
//         TSocket socket(TAddress{"3.224.224.8", 80}, loop->Poller());
//         co_await socket.Connect();

//         string request = R"(GET /get HTTP/1.1
// Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
// Accept-Encoding: gzip, deflate
// Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
// Cache-Control: max-age=0
// Connection: keep-alive
// Host: httpbin.org
// Upgrade-Insecure-Requests: 1
// User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0)

// )";

//         size = co_await socket.WriteSome(request.data(), request.size());
//         // size = co_await socket.ReadSome(&p, sizeof(payload));

//         do
//         {
//             size = co_await read_some(socket);
//             // char buf[1024];
//             // size = co_await socket.ReadSome(buf, sizeof(buf));
//             // std::cout << "Received: " << size << " bytes\n";
//             // std::cout << string(buf, size) << "\n";
//         } while (size > 0);

//         // TLineReader lineReader(socket, 10'000);

//         // co_await socket.Connect();
//         // while (auto line = co_await lineReader.Read())
//         // {
//         //     std::cout << "Received: " << line << "\n";
//         // }

//         // co_await loop->Poller().Sleep(std::chrono::milliseconds(1000));
//     }
//     catch (const std::exception& ex)
//     {
//         std::cout << "Exception: " << ex.what() << "\n";
//     }

//     std::cout << "Client done: " << size << "\n";
//     co_return;
// }

// int main()
// {
//     signal(SIGPIPE, SIG_IGN);

//     Loop loop;
//     client(&loop);
//     loop.Loop();

//     return 0;
// }
