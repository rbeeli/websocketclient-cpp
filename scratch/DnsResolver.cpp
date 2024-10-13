#include <iostream>

#include "ws_client/errors.hpp"
#include "ws_client/log.hpp"
#include "ws_client/transport/builtin/DnsResolver.hpp"

using namespace ws_client;

int main()
{
    try
    {
        auto res = DnsResolver::resolve("example.com", "80", AddrType::unspecified);
        if (!res)
        {
            std::cerr << "Failed to resolve hostname: " << res.error() << std::endl;
            return 1;
        }

        for (const auto& addr : res.value())
        {
            std::cout << addr << std::endl;
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }
    return 0;
}
