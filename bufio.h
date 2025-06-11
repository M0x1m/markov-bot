#ifndef BUFIO_H_
#define BUFIO_H_

#include <stddef.h>

struct bufio {
    void *handler;
    int (*read)(void *, void *, int);
    void (*write)(void *, const void *, int);
    int rb_avail, rb_pos;
    int wb_avail, wb_pos;
    char readbuf[4096];
    char writebuf[4096];
};

void bio_init(struct bufio *, void *, int (*)(void *, void *, int), void (*)(void *, const void *, int));
void bio_read(struct bufio *, void *, int);
void bio_send(struct bufio *, const void *, int);
void bio_flush(struct bufio *);
int bio_read_until(struct bufio *, void *, const char*, size_t);

#endif
