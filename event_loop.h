#ifndef EVENT_LOOP_H_
#define EVENT_LOOP_H_

#include "libco/libco.h"
#include <setjmp.h>
#include <poll.h>
#include <fcntl.h>

#ifndef POLLABLE_STACK_SIZE
#define POLLABLE_STACK_SIZE 8192
#endif

struct event_loop;

struct pollable {
    int fd;
    int flags;
    int finished;
    int timeout;
    int elapsed;
    jmp_buf on_closed;
    struct event_loop *el;
    cothread_t poll_ctx;
    char stack[POLLABLE_STACK_SIZE];
};

struct event_loop {
    struct pollable **items;
    size_t count;
    size_t capacity;
    cothread_t ctx;
};

void pollable_cleanup(void (*func)(struct pollable *, void *), struct pollable *this, void *data);
void event_loop_add(struct event_loop *el, int fd, int fl, void (*func)(struct pollable *, void *), void *data);
void event_loop_next(struct event_loop *el);

#ifdef EVENT_LOOP_IMPLEMENTATION
struct libco_wrapper_closure {
    void (*func)(struct pollable *, void *);
    struct pollable *this;
    void *data;
    cothread_t init;
};

static struct libco_wrapper_closure __libco_wrapper_closure;

void libco_wrapper(void)
{
    struct libco_wrapper_closure wrapper_closure = __libco_wrapper_closure;
    struct pollable *this = wrapper_closure.this;

    co_switch(wrapper_closure.init);

    wrapper_closure.func(this, wrapper_closure.data);
}

void event_loop_add(struct event_loop *el, int fd, int fl, void (*func)(struct pollable *, void *), void *data)
{
    struct pollable *p = malloc(sizeof *p);
    memset(p, 0, sizeof(*p));

    p->fd = fd;
    p->flags = fl;
    p->el = el;
    if (p->fd >= 0) p->timeout = -1;

    p->poll_ctx = co_derive(p->stack, sizeof p->stack, libco_wrapper);

    __libco_wrapper_closure.this = p;
    __libco_wrapper_closure.data = data;
    __libco_wrapper_closure.func = func;
    __libco_wrapper_closure.init = co_active();

    co_switch(p->poll_ctx);
    da_append(el, p);
}

void event_loop_next(struct event_loop *el)
{
    struct pollfd pfds[64] = {0};
    int finished[ARRAY_LEN(pfds)];
    int finished_len = 0;

    assert(el->count <= ARRAY_LEN(pfds) && "Too many fildes");

    int timeout = -1;
    for (size_t i = 0; i < el->count; ++i) {
        struct pollable *this = el->items[i];
        pfds[i].fd = this->fd;
        pfds[i].events = this->flags;
        if (this->timeout < 0) continue;

        int remaining = this->timeout - this->elapsed;
        if (remaining < 0) remaining = 0;
        if (timeout == -1 || timeout > remaining) {
            timeout = remaining;
        }
    }

    struct timespec begin, end;
    clock_gettime(CLOCK_MONOTONIC, &begin);

    poll(pfds, el->count, timeout);

    clock_gettime(CLOCK_MONOTONIC, &end);
    int ms_passed = (end.tv_sec - begin.tv_sec) * 1000 + (end.tv_nsec - begin.tv_nsec) / 1000000;
    for (size_t i = 0; i < el->count; ++i) {
        struct pollable *const c = el->items[i];
        c->elapsed += ms_passed;
        const int ready = pfds[i].revents;
        const int timed_out = c->timeout >= 0 && c->elapsed >= c->timeout;
        if (!ready && !timed_out) continue;

        c->flags = pfds[i].revents;
        co_switch(c->poll_ctx);
        c->elapsed = 0;

        if (!c->finished) continue;
        finished[finished_len++] = i;
        free(c);
    }

    for (size_t i = finished_len; i > 0; --i) {
        el->items[finished[i - 1]] = el->items[--el->count];
    }
}
#endif // EVENT_LOOP_IMPLEMENTATION

#endif // EVENT_LOOP_H_
