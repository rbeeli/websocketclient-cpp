#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <netdb.h>
#include <atomic>
#include <arpa/inet.h>

struct async_getaddrinfo_state
{
    struct gaicb gai_request; // call gai_cancel(&gai_request) to cancel
    struct gaicb* gai_requests;
    struct sigevent sigevent;

    void (*callback)(void*, int, struct addrinfo*);
    void* context;
};

static void async_getaddrinfo_complete(union sigval context)
{
    struct async_getaddrinfo_state* state = (struct async_getaddrinfo_state*)context.sival_ptr;

    std::atomic_thread_fence(std::memory_order::acquire);

    int res = gai_error(&state->gai_request);

    void (*callback)(void*, int, struct addrinfo*) = state->callback;
    void* callback_context = state->context;
    struct addrinfo* info = res == 0 ? state->gai_request.ar_result : NULL;

    free(state);

    callback(callback_context, res, info);
}

static int async_getaddrinfo(
    const char* name,
    const char* service,
    const struct addrinfo* hints,
    void (*callback)(void*, int, struct addrinfo*),
    void* context
)
{
    struct async_getaddrinfo_state* state =
        (async_getaddrinfo_state*)malloc(sizeof(struct async_getaddrinfo_state));

    state->gai_request.ar_name = name;
    state->gai_request.ar_service = service;
    state->gai_request.ar_request = hints;
    state->gai_request.ar_result = NULL;
    state->gai_requests = &state->gai_request;

    state->sigevent.sigev_notify = SIGEV_THREAD;
    state->sigevent.sigev_value.sival_ptr = state;
    state->sigevent.sigev_notify_function = async_getaddrinfo_complete;

    state->callback = callback;
    state->context = context;

    std::atomic_thread_fence(std::memory_order::release);

    int res = getaddrinfo_a(GAI_NOWAIT, &state->gai_requests, 1, &state->sigevent);

    if (res != 0)
    {
        free(state);
    }

    return res;
}

struct test_all_state
{
    sem_t semaphore;
    std::atomic<uint32_t> completed;
};

struct test_one_state
{
    struct test_all_state* all_state;
    const char* host;
};

static void test_onresolve(void* context, int result, struct addrinfo* info)
{
    int thread_id = pthread_self();

    struct test_one_state* state = (struct test_one_state*)context;

    if (result == 0)
    {
        for (struct addrinfo* iter = info; iter; iter = iter->ai_next)
        {
            void* addr_ptr = NULL; // Pointer to the address structure.

            switch (iter->ai_family)
            {
                case AF_INET: // IPv4
                    addr_ptr = &((struct sockaddr_in*)iter->ai_addr)->sin_addr;
                    break;
                case AF_INET6: // IPv6
                    addr_ptr = &((struct sockaddr_in6*)iter->ai_addr)->sin6_addr;
                    break;
                default:
                    continue; // Skip non-IPv4/IPv6 addresses.
            }

            if (addr_ptr)
            {
                char buffer[INET6_ADDRSTRLEN]; // Use larger buffer for IPv6.
                const char* ip_str = inet_ntop(
                    iter->ai_family,
                    addr_ptr, // Use the generic pointer to the address.
                    buffer,
                    sizeof(buffer)
                );
                if (ip_str != NULL) // Check for success.
                {
                    printf("(%d) [%s] %s\n", thread_id, state->host, buffer);
                }
                else
                {
                    perror("inet_ntop failed");
                }
            }
        }

        freeaddrinfo(info);
    }

    if (atomic_fetch_add(&state->all_state->completed, 1) + 1 == 2) // Ensure both are completed.
    {
        sem_post(&state->all_state->semaphore);
    }
}


int main(void)
{
    struct test_all_state state;
    sem_init(&state.semaphore, 0, 0);
    state.completed = 0;

    struct addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_socktype = SOCK_STREAM;

    struct test_one_state stateA = {&state, "contoso.com"};
    int resA = async_getaddrinfo(stateA.host, NULL, &hints, test_onresolve, &stateA);

    struct test_one_state stateB = {&state, "microsoft.com"};
    int resB = async_getaddrinfo(stateB.host, NULL, &hints, test_onresolve, &stateB);

    printf("resA: %d, resB: %d\n", resA, resB);

    if (resA != 0 || resB != 0)
        return 0;

    sem_wait(&state.semaphore);
    sem_destroy(&state.semaphore);

    return 0;
}