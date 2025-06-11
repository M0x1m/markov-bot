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
    p->timeout = -1;

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
        if (timeout == -1 || timeout > this->timeout) {
            timeout = this->timeout;
        }
    }

    poll(pfds, el->count, timeout);
    for (size_t i = 0; i < el->count; ++i) {
        if (!pfds[i].revents && pfds[i].fd >= 0) continue;
        struct pollable *current = el->items[i];

        current->flags = pfds[i].revents;
        co_switch(current->poll_ctx);
        if (!current->finished) continue;
        finished[finished_len++] = i;
        free(current);
    }

    for (size_t i = finished_len; i > 0; --i) {
        el->items[finished[i - 1]] = el->items[--el->count];
    }
}
#endif // EVENT_LOOP_IMPLEMENTATION

#endif // EVENT_LOOP_H_
