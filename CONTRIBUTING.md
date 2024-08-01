# Contributing

Pull requests and issues are welcome.

## TODOs

- Git builds
- auto fragmentation write
- timeout for DnsResolver

- SSL_shutdown sig pipe

  - https://stackoverflow.com/questions/108183/how-to-prevent-sigpipes-or-handle-them-properly
  - BIO_free_all(this->web); // TODO throws sometimes, e.g. websocketclient init error

    NOTE: When using SSL, it seems impossible to avoid SIGPIPE in all cases, since on some operating systems, SIGPIPE can only be suppressed on a per-message basis, but there is no way to make the OpenSSL library do so for its internal communications. If your program needs to avoid being terminated on SIGPIPE, the only fully general way might be to set up a signal handler for SIGPIPE to handle or ignore it yourself.

    OpenSslSocket.hpp: Use custom BIO to allow setting MSG_NOSIGNAL

## Useful resources

- https://jamespascoe.github.io/accu2023/#/9/2/3
- https://habr.com/en/articles/768418/
- https://dzone.com/articles/implementation-of-the-raft-consensus-algorithm-usi

## WebSocket connections inspection and testing

Lists all connections:

```bash
sudo ss -tp | grep main_demo
```

Closes WebSocket connection at port 443 of process:

```bash
sudo ss -tp | grep "pid=$(pidof bybit_orderbook)" | grep -oP '\s\K[^ ]+(?=:https)'443

sudo ss -K dst $(sudo ss -tp | grep "pid=$(pidof bybit_orderbook)" | grep -oP '\s\K[^ ]+(?=:https)') dport = 443

sudo ss -K dst '127.0.0.1' dport = 443

sudo ss -K dst 66.241.124.119:443

pidof bybit_orderbook
```

## Compiler varia

Debug clang header lookup paths:

```bash
clang++ -stdlib=libc++ -std=c++23 -v -E -x c++ /dev/null
```

Install libc++19:

```bash
sudo apt-get install libc++-19-dev libc++abi-19-dev
```
