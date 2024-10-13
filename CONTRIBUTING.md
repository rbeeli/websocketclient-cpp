# Contributing

Pull requests and issues are welcome.

## TODOs

- Source location in logging seems off
- More default logging of control frames
- Git automatic builds
- Auto fragmentation when writing large messages?
- Timeout support for DnsResolver

## Useful resources

- https://jamespascoe.github.io/accu2023/#/9/2/3
- https://habr.com/en/articles/768418/
- https://dzone.com/articles/implementation-of-the-raft-consensus-algorithm-usi

## WebSocket connections inspection and testing

Lists all connections:

```bash
sudo ss -tp | grep "pid=$(pidof ex_reconnect_asio)"
sudo ss -tp | grep "pid=$(pidof ex_binance_builtin)"
```

Closes WebSocket connection at port 443 of process:

```bash
sudo ss -tp | grep "pid=$(pidof ex_reconnect_asio)" | grep -oP '\s\K[^ ]+(?=:https)'
sudo ss -tp | grep "pid=$(pidof ex_binance_builtin)" | grep -oP '\s\K[^ ]+(?=:https)'

sudo ss -K dst $(sudo ss -tp | grep "pid=$(pidof ex_reconnect_asio)" | grep -oP '\s\K[^ ]+(?=:https)') dport = 443
sudo ss -K dst $(sudo ss -tp | grep "pid=$(pidof ex_binance_builtin)" | grep -oP '\s\K[^ ]+(?=:https)') dport = 443

sudo ss -K dst $(sudo ss -tp | grep "pid=$(pidof ex_hello_ws_builtin)" | grep -oP '\s\K[^ ]+(?=:http)') dport = 8080

sudo ss -K dst '127.0.0.1' dport = 443

sudo ss -K dst 66.241.124.119:443

pidof ex_echo_builtin
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
