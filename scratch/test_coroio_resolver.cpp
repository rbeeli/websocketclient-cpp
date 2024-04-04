#include <span>
#include <string>
#include <iostream>

#include "coroio/resolver.hpp"
#include "coroio/all.hpp"

using namespace NNet;

struct TLine
{
    std::string_view Part1;
    std::string_view Part2;

    size_t Size() const
    {
        return Part1.size() + Part2.size();
    }

    operator bool() const
    {
        return !Part1.empty();
    }
};

struct TZeroCopyLineSplitter
{
public:
    TZeroCopyLineSplitter(int maxLen);

    TLine Pop();
    std::span<char> Acquire(size_t size);
    void Commit(size_t size);
    void Push(const char* p, size_t len);

private:
    size_t WPos;
    size_t RPos;
    size_t Size;
    size_t Cap;
    std::string Data;
    std::string_view View;
};


template <typename TSocket>
struct TLineReader
{
    TLineReader(TSocket& socket, int maxLineSize = 4096)
        : Socket(socket), Splitter(maxLineSize), ChunkSize(maxLineSize / 2)
    {
    }

    TValueTask<TLine> Read()
    {
        auto line = Splitter.Pop();
        while (!line)
        {
            auto buf = Splitter.Acquire(ChunkSize);
            auto size = co_await Socket.ReadSome(buf.data(), buf.size());
            if (size < 0)
            {
                continue;
            }
            if (size == 0)
            {
                break;
            }
            Splitter.Commit(size);
            line = Splitter.Pop();
        }
        co_return line;
    }

private:
    TSocket& Socket;
    TZeroCopyLineSplitter Splitter;
    int ChunkSize;
};


TZeroCopyLineSplitter::TZeroCopyLineSplitter(int maxLen)
    : WPos(0)
    , RPos(0)
    , Size(0)
    , Cap(maxLen * 2)
    , Data(Cap, 0)
    , View(Data)
{ }

TLine TZeroCopyLineSplitter::Pop() {
    auto end = View.substr(RPos, Size);
    auto begin = View.substr(0, Size - end.size());

    auto p1 = end.find('\n');
    if (p1 == std::string_view::npos) {
        auto p2 = begin.find('\n');
        if (p2 == std::string_view::npos) {
            return {};
        }

        RPos = p2 + 1;
        Size -= end.size() + p2 + 1;
        return TLine { end, begin.substr(0, p2 + 1) };
    } else {
        RPos += p1 + 1;
        Size -= p1 + 1;
        return TLine { end.substr(0, p1 + 1), {} };
    }
}

std::span<char> TZeroCopyLineSplitter::Acquire(size_t size) {
    size = std::min(size, Cap - Size);
    if (size == 0) {
        throw std::runtime_error("Overflow");
    }
    auto first = std::min(size, Cap - WPos);
    if (first) {
        return {&Data[WPos], first};
    } else {
        return {&Data[0], size};
    }
}

void TZeroCopyLineSplitter::Commit(size_t size) {
    WPos = (WPos + size) % Cap;
    Size += size;
}

void TZeroCopyLineSplitter::Push(const char* p, size_t len) {
    while (len != 0) {
        auto buf = Acquire(len);
        memcpy(buf.data(), p, buf.size());
        Commit(buf.size());
        len -= buf.size();
        p += buf.size();
    }
}













template <typename TResolver>
TVoidTask resolve(TResolver& resolver, std::string name, EDNSType type, int* inflight)
{
    try
    {
        auto addrs = co_await resolver.Resolve(name, type);
        std::cout << "'" << name << "': ";
        for (auto& a : addrs)
        {
            std::cout << a.ToString() << ", ";
        }
    }
    catch (const std::exception& ex)
    {
        std::cout << "'" << name << "': ";
        std::cout << ex.what();
    }
    std::cout << "\n";
    --(*inflight);
    co_return;
}

template <typename TPoller>
TVoidSuspendedTask resolve(TPoller& poller, EDNSType type)
{
    TFileHandle input{0, poller}; // stdin
    TLineReader lineReader(input, 4096);
    TResolver<TPollerBase> resolver(poller);
    int inflight = 0;
    while (auto line = co_await lineReader.Read())
    {
        inflight++;
        std::string name = std::string(line.Part1);
        name += line.Part2;
        name.resize(name.size() - 1);
        resolve(resolver, std::move(name), type, &inflight);
    }
    while (inflight != 0)
    {
        co_await poller.Yield();
    }
    co_return;
}

template <typename TPoller>
void run(EDNSType type)
{
    TLoop<TPoller> loop;
    auto task = resolve(loop.Poller(), type);
    while (!task.done())
    {
        loop.Step();
    }
    task.destroy();
}

int main()
{
    EDNSType type = EDNSType::A;
    run<TEPoll>(type);
    return 0;
}
