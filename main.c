#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <json-c/json.h>

#include "bufio.h"
#include "bufio.c"

#include "libco/libco.h"
#include "libco/libco.c"

#define UTILS_IMPLEMENTATION
#define UTILS_DISABLE_ZLIB
#define UTILS_DEF static inline
#include "utils.h"

#define POLLABLE_STACK_SIZE 65536
#define EVENT_LOOP_IMPLEMENTATION
#include "event_loop.h"

#define HOST "api.telegram.org"

#define WINDOW_SIZE 8

int get_addr(const char *name)
{
    struct addrinfo hint = {0};
    hint.ai_family = AF_INET;

    struct addrinfo *result;
    int ret = getaddrinfo(name, NULL, &hint, &result);
    if (ret) return -1;

    return ((struct sockaddr_in*)result->ai_addr)->sin_addr.s_addr;
}

struct secure_fd {
    SSL *ssl;
    struct pollable *pollable;
};

struct markov_prefix_child {
    int key;
    uint64_t freq;
};

struct markov_prefix_children {
    struct markov_prefix_child *items;
    uint8_t *bitmap;
    uint64_t (*hashf)(const void *);
    int (*compare)(const void *, const void *);
    void *(*alloc)(void *, size_t);
    void (*free)(void *, void *, size_t);
    void *ator;
    size_t count;
    size_t capacity;
};

struct markov_prefixes {
    int key[WINDOW_SIZE];
    uint64_t freq;
    struct markov_prefix_children values;
};

int compare_prefixes(const void *p1, const void *p2)
{
    const struct markov_prefixes *ps1 = p1;
    const struct markov_prefixes *ps2 = p2;

    return memcmp(ps1->key, ps2->key, sizeof ps1->key);
}

uint64_t hashf_prefixes(const void *prefixes)
{
    static int seed = 0;

    if (seed == 0) {
        RAND_bytes((void *) &seed, sizeof seed);
    }

    const struct markov_prefixes *ps = prefixes;
    return murmur3_32((void *) ps->key, sizeof ps->key, seed);
}

int compare_prefix_child(const void *p1, const void *p2)
{
    const struct markov_prefix_child *c1 = p1, *c2 = p2;

    return c1->key - c2->key;
}

uint64_t hashf_prefix_child(const void *c)
{
    static int seed = 0;

    if (seed == 0) {
        RAND_bytes((void *) &seed, sizeof seed);
    }

    const struct markov_prefix_child *ch = c;
    return murmur3_32((void *) &ch->key, sizeof ch->key, seed);
}

void init_prefix_children(struct markov_prefix_children *cn)
{
    memset(cn, 0, sizeof *cn);

    cn->compare = compare_prefix_child;
    cn->hashf = hashf_prefix_child;
}

struct markov_chain {
    struct markov_prefixes *items;
    uint8_t *bitmap;
    uint64_t (*hashf)(const void *);
    int (*compare)(const void *, const void *);
    void *(*alloc)(void *, size_t);
    void (*free)(void *, void *, size_t);
    void *ator;
    size_t count;
    size_t capacity;
    uint64_t freq;
};

struct bot {
    const char *token;
    SSL_CTX *ssl_ctx;
    struct event_loop el;
    int last_confirmed;
    struct markov_chain mc;
    int window[WINDOW_SIZE];
    int64_t prompt_chat_id;
    uint64_t prompt_secret;
};

typedef struct {
    struct bot *bot;
    struct pollable *pollable;
    struct bufio *bio;
    arena a;
} bot_async_ctx;
typedef void (*bot_async_fn)(bot_async_ctx *, void *);

#define ASYNC_SSL(ssl, ssl_call, pctx)                          \
    do {                                                        \
        int _ret;                                               \
        while ((_ret = (ssl_call)) < 0) {                       \
            switch (SSL_get_error(ssl, _ret)) {                 \
            case SSL_ERROR_WANT_WRITE:                          \
                (pctx)->flags = POLLOUT;                        \
                break;                                          \
            case SSL_ERROR_WANT_READ:                           \
                (pctx)->flags = POLLIN;                         \
                break;                                          \
            default: longjmp((pctx)->on_closed, 1);             \
            }                                                   \
            co_switch((pctx)->el->ctx);                         \
            if ((pctx)->flags == 0) {  /* Timed out */          \
                longjmp((pctx)->on_closed, 1);                  \
            }                                                   \
        }                                                       \
    } while (0)

int file_read_unicode(FILE *f)
{
    uint32_t c = fgetc(f);

    if (!(c >> 7))        return c;
    if ((c >> 5) == 6)    return (c & 0x1f) << 6 | (fgetc(f) & 0x3f);
    if ((c >> 4) == 0xe)  return (c & 0xf) << 12 | (fgetc(f) & 0x3f) << 6 | (fgetc(f) & 0x3f);
    if ((c >> 3) == 0x1e) return (c & 0x7) << 18 | (fgetc(f) & 0x3f) << 12
                              | (fgetc(f) & 0x3f) << 6 | (fgetc(f) & 0x3f);
    return -1;
}

void bytes_append_utf8_codepoint(bot_async_ctx *ctx, struct bytes_array *a, uint32_t c)
{
    int b = 0, l = 0;
    while (c>>++b)
        ;;
    int t = (b > 7) | (b > 11) << 1 | (b > 16) << 2;
    while (t>>l++)
        ;;

    switch (l) {
    case 1: da_append2(a, c, &ctx->a, arena_realloc); break;
    case 2: {
        uint32_t x = c >> 6 | (c & 0x3f) << 8 | 0x80c0;
        da_append_many2(a, &x, 2, &ctx->a, arena_realloc);
    } break;
    case 3: {
        uint32_t x = c >> 12 | (c >> 6 & 0x3f) << 8 | (c & 0x3f) << 16 | 0x8080e0;
        da_append_many2(a, &x, 3, &ctx->a, arena_realloc);
    } break;
    case 4: {
        uint32_t x = c >> 18 | (c >> 12 & 0x3f) << 8 | (c >> 6 & 0x3f) << 16 | (c & 0x3f) << 24 | 0x808080f0;
        da_append_many2(a, &x, 4, &ctx->a, arena_realloc);
    } break;
    }
}

int kernel_move(int (*kernel)[WINDOW_SIZE], int c)
{
    int r = **kernel;
    memmove(*kernel, *kernel + 1, (WINDOW_SIZE - 1) * sizeof **kernel);
    (*kernel)[WINDOW_SIZE - 1] = c;
    return r;
}

void bot_feed_code(struct bot *bot, int codepoint)
{
    if (!bot->window[WINDOW_SIZE - 1]) {
        int l = 0;
        while (bot->window[l]) l++;
        bot->window[l] = codepoint;
        return;
    }

    bot->mc.freq++;

    struct markov_prefix_child *f, c;
    struct markov_prefixes *ps, x;

    ps = hashmap_get(&bot->mc, bot->window);
    if (!ps) {
        init_prefix_children(&x.values);
        memcpy(x.key, bot->window, sizeof x.key);
        x.freq = 1;
        c.freq = 1;
        c.key = codepoint;
        hashmap_insert(&x.values, &c);
        hashmap_insert(&bot->mc, &x);
        goto window_move;
    }

    ps->freq++;

    f = hashmap_get(&ps->values, &codepoint);
    if (f) {
        f->freq++;
        goto window_move;
    }

    c.freq = 1;
    c.key = codepoint;
    hashmap_insert(&ps->values, &c);

 window_move:

    kernel_move(&bot->window, codepoint);
}

int bot_feed_file(struct bot *bot, const char *name)
{
    FILE *f = fopen(name, "rb");
    if (f == NULL) return -1;
    while (!feof(f)) bot_feed_code(bot, file_read_unicode(f));
    fclose(f);

    return 0;
}

int secure_read(void *handle, void *buf, int count)
{
    struct secure_fd *fd = handle;
    int ret;

    ASYNC_SSL(fd->ssl, (ret = SSL_read(fd->ssl, buf, count)), fd->pollable);

    return ret;
}

void secure_write(void *handle, const void *buf, int count)
{
    struct secure_fd *fd = handle;
    int ret;
    int off = 0;

    while (off < count) {
        ASYNC_SSL(fd->ssl, (ret = SSL_write(fd->ssl, (char*)buf + off, count - off)), fd->pollable);
        off += ret;
    }
}

int bot_receive_events(struct bot *);
int bot_add_net_task(struct bot *bot, bot_async_fn func, void *func_data);

void bio_send_cstr(struct bufio *bio, const char *cstr)
{
    bio_send(bio, cstr, strlen(cstr));
}

void async_bot_telegram_post_method(bot_async_ctx *ctx, const char *method, json_object *obj)
{
    char *buf = arena_alloc(&ctx->a, 256);

    struct bufio *bio = ctx->bio;
    const char *body = json_object_to_json_string(obj);

    bio_send_cstr(bio, "POST /bot");
    bio_send_cstr(bio, ctx->bot->token);
    bio_send_cstr(bio, "/");
    bio_send_cstr(bio, method);
    bio_send_cstr(bio, " HTTP/1.1\r\n");
    bio_send_cstr(bio, "Host: "HOST"\r\n");
    bio_send_cstr(bio, "Content-Type: application/json\r\n");
    sprintf(buf, "Content-Length: %ld\r\n", strlen(body));
    bio_send_cstr(bio, buf);
    bio_send_cstr(bio, "Connection: keep-alive\r\n\r\n");
    bio_send_cstr(bio, body);
    printf("Body: %s\n", body);
}

int http_get_content_length(bot_async_ctx *ctx)
{
    string_view res;
    res.data = arena_alloc(&ctx->a, 8192);
    res.count = bio_read_until(ctx->bio, (char *) res.data, "\r\n\r\n", 8192);

    sv_chop_by_delim(&res, '\n'); // Status line
    res = sv_trim(res);
    while (res.count) {
        string_view header = sv_chop_by_delim(&res, '\n');
        res = sv_trim(res);

        string_view name = sv_chop_by_delim(&header, ':');
        if (!sv_eq_cstr(name, "Content-Length")) continue;

        sv_chop(&header, 1);
        string_view value = sv_trim(header);
        return sv_to_int(value);
    }

    longjmp(ctx->pollable->on_closed, 1);
}

struct bot_send_message_closure {
    string_view message;
    int64_t chat_id;
};

void async_bot_send_message(bot_async_ctx *ctx, void *data)
{
    struct bot_send_message_closure msg = *(struct bot_send_message_closure *)data;
    char *new_message_data = arena_alloc(&ctx->a, msg.message.count);
    memcpy(new_message_data, msg.message.data, msg.message.count);
    msg.message.data = new_message_data;
    free(data);

    json_object *message = json_object_new_object();
    json_object_object_add(message, "chat_id", json_object_new_int64(msg.chat_id));
    json_object *text = json_object_new_string_len(msg.message.data, msg.message.count);
    json_object_object_add(message, "text", text);

    async_bot_telegram_post_method(ctx, "sendMessage", message);
    json_object_put(message);

    bio_flush(ctx->bio);

    string_view body;

    body.count = http_get_content_length(ctx);
    body.data = arena_alloc(&ctx->a, body.count);
    bio_read(ctx->bio, (char *) body.data, body.count);
}

int bot_send_message_sv(struct bot *bot, int64_t chat_id, string_view msg)
{
    struct bot_send_message_closure *data = malloc(sizeof *data + msg.count);
    data->chat_id = chat_id;
    data->message.count = msg.count;
    data->message.data = (char *)(data + 1);
    memcpy((void *) data->message.data, msg.data, msg.count);

    return bot_add_net_task(bot, async_bot_send_message, data);
}

int bot_send_message(struct bot *bot, int64_t chat_id, const char *msg)
{
    return bot_send_message_sv(bot, chat_id, sv_from_cstr(msg));
}

int markov_generate_subseq(struct bot *bot, int (*kernel)[WINDOW_SIZE])
{
    uint32_t r;
    struct markov_prefixes *prefixes;
    struct markov_prefix_child *child = NULL;

    prefixes = hashmap_get(&bot->mc, *kernel);
    if (!prefixes) return -1;
    RAND_bytes((void *) &r, sizeof r);

    r %= prefixes->freq;

    for (size_t i = 0, k = 0; i < prefixes->values.capacity && k < prefixes->values.count; ++i) {
        if (!hashmap_have_index(&prefixes->values, i)) {continue;} k++;

         child = &prefixes->values.items[i];
         if (child->freq > r) break;
         r -= child->freq;
    }

    kernel_move(kernel, child->key);
    return child->key;
}

void markov_generate_kernel(struct bot *bot, int (*kernel)[WINDOW_SIZE])
{
    uint32_t r;
    struct markov_prefixes *prefixes = NULL;
    RAND_bytes((void *) &r, sizeof r);

    r %= bot->mc.freq;

    for (size_t i = 0, k = 0; i < bot->mc.capacity && k < bot->mc.count; ++i) {
        if (!hashmap_have_index(&bot->mc, i)) {continue;} k++;

        prefixes = &bot->mc.items[i];
        if (r < prefixes->freq) break;
        r -= prefixes->freq;
    }

    memcpy(*kernel, prefixes->key, sizeof *kernel);
}

void kernel_append(bot_async_ctx *ctx, struct bytes_array *acc, int (*kernel)[WINDOW_SIZE])
{
    for (int i = 0; i < WINDOW_SIZE; ++i) {
        bytes_append_utf8_codepoint(ctx, acc, (*kernel)[i]);
    }
}

int kernel_compare(int (*k1)[WINDOW_SIZE], int (*k2)[WINDOW_SIZE])
{
    int i;
    for (i = 0; i < WINDOW_SIZE; ++i) {
        if ((*k1)[i] != (*k2)[i]) break;
    }
    return i;
}

void markov_custom_kernel(bot_async_ctx *ctx, struct bytes_array *acc, int (*kernel)[WINDOW_SIZE], string_view cmd)
{
    memset(*kernel, 0, sizeof *kernel);
    struct bot *bot = ctx->bot;

    while (cmd.count) {
        int r = kernel_move(kernel, sv_read_unicode(&cmd));
        if (r) bytes_append_utf8_codepoint(ctx, acc, r);
    }
    while (!**kernel) kernel_move(kernel, 0);

    int max_similar = 0;
    struct markov_prefixes *most_similar = NULL, *prefixes = NULL;

    for (size_t i = 0, k = 0; i < bot->mc.capacity && k < bot->mc.count; ++i) {
        if (!hashmap_have_index(&bot->mc, i)) {continue;} k++;

        prefixes = &bot->mc.items[i];
        int c = kernel_compare(kernel, &prefixes->key);
        if (c <= max_similar) continue;
        max_similar = c;
        most_similar = prefixes;
    }

    if (!most_similar) {
        acc->count = 0;
        markov_generate_kernel(bot, kernel);
        return;
    }

    memcpy(*kernel, most_similar->key, sizeof *kernel);
}

void bot_carrot_command(bot_async_ctx *ctx, int64_t chat_id, string_view cmd)
{
    struct bot *bot = ctx->bot;

    if (!bot->mc.count) {
        bot_send_message(bot, chat_id, "The Markov Chain is too small to produce anything");
        return;
    }

    uint32_t sym;
    RAND_bytes((void *) &sym, sizeof sym);
    sym = sym % (800 - 500) + 500;

    struct bytes_array acc = {0};
    int kernel[WINDOW_SIZE];

    if (cmd.count) markov_custom_kernel(ctx, &acc, &kernel, cmd);
    else markov_generate_kernel(bot, &kernel);
    kernel_append(ctx, &acc, &kernel);

    for (uint32_t i = 0; i < sym; ++i) {
        int s = markov_generate_subseq(bot, &kernel);
        if (s == -1) break;
        bytes_append_utf8_codepoint(ctx, &acc, s);
    }

    da_append2(&acc, 0, &ctx->a, arena_realloc);
    bot_send_message(bot, chat_id, acc.items);
}

void markov_save_prefixes(FILE *f, struct markov_prefixes *prefixes)
{
    for (size_t i = 0, k = 0; i < prefixes->values.capacity && k < prefixes->values.count; ++i) {
        if (!hashmap_have_index(&prefixes->values, i)) {continue;} k++;

        struct markov_prefix_child *child = &prefixes->values.items[i];
        for (int j = 0; j < WINDOW_SIZE; ++j) {
            if (j) fputc(',', f);
            fprintf(f, "%d", prefixes->key[j]);
        }

        fprintf(f, ":%d/%zu\n", child->key, child->freq);
    }
}

#define MARKOV_CHAIN_PATH "markov_chain"

int bot_save_markov(struct bot *bot)
{
    FILE *f = fopen(MARKOV_CHAIN_PATH, "wb");
    if (!f) return -1;

    for (size_t i = 0, k = 0; i < bot->mc.capacity && k < bot->mc.count; ++i) {
        if (!hashmap_have_index(&bot->mc, i)) {continue;} k++;

        struct markov_prefixes *prefixes = &bot->mc.items[i];
        markov_save_prefixes(f, prefixes);
    }

    fclose(f);

    return 0;
}

int markov_parse_child(struct bot *bot, string_view row)
{
    int kernel[WINDOW_SIZE];
    string_view kernel_sv = sv_chop_by_delim(&row, ':');
    sv_chop(&row, 1);
    for (int i = 0; i < WINDOW_SIZE; ++i) {
        if (!kernel_sv.count) return -1;
        string_view n = sv_chop_by_delim(&kernel_sv, ',');
        sv_chop(&kernel_sv, 1);
        kernel[i] = sv_to_int(n);
    }

    if (kernel_sv.count) return -1;

    struct markov_prefix_child child;
    struct markov_prefixes *p, np;

    child.key = sv_to_int(sv_chop_by_delim(&row, '/'));
    sv_chop(&row, 1);
    child.freq = sv_to_u64(row);
    bot->mc.freq += child.freq;

    p = hashmap_get(&bot->mc, kernel);
    if (!p) {
        init_prefix_children(&np.values);
        memcpy(np.key, kernel, sizeof np.key);
        np.freq = child.freq;
        hashmap_insert(&np.values, &child);
        hashmap_insert(&bot->mc, &np);

        return 0;
    }

    p->freq += child.freq;
    hashmap_insert(&p->values, &child);

    return 0;
}

int bot_load_markov(bot_async_ctx *ctx)
{
    FILE *f = fopen(MARKOV_CHAIN_PATH, "rb");
    if (!f) return -1;

    char *buf = arena_alloc(&ctx->a, 1024);

    while (!feof(f)) {
        fgets(buf, 1024, f);
        string_view row = sv_from_cstr(buf);

        if (markov_parse_child(ctx->bot, row) < 0) return -2;
    }

    fclose(f);

    return 0;
}

void bot_handle_message(bot_async_ctx *ctx, int64_t chat_id, string_view text)
{
    struct bot *bot = ctx->bot;

    if (!bot->prompt_chat_id) {
        if (bot->prompt_secret == sv_to_u64(sv_trim(text))) {
            bot->prompt_chat_id = chat_id;
            bot_send_message(bot, chat_id, "This chat is prompt now");
            return;
        }
    }

    int prompt_chat = bot->prompt_chat_id == chat_id;

    if (chat_id < 0 && chat_id != -1002207125722) return;

    string_view cmd = text;
    string_view command = sv_chop_by_delim(&cmd, ' ');
    char *buf = arena_alloc(&ctx->a, 8192);
    cmd = sv_trim(cmd);

    if (prompt_chat && sv_eq_cstr(command, "save")) {
        if (bot_save_markov(bot) >= 0) {
            bot_send_message(bot, chat_id, "Markov chain is saved");
            return;
        }

        snprintf(buf, 8192, "Could not save markov chain: %s", strerror(errno));
        bot_send_message(bot, chat_id, buf);
        return;
    }

    if (prompt_chat && sv_eq_cstr(command, "load")) {
        int ret = bot_load_markov(ctx);
        if (ret >= 0) {
            bot_send_message(bot, chat_id, "Markov chain loaded");
            return;
        }

        if (ret == -1) snprintf(buf, 8192, "Could not load markov chain: %s", strerror(errno));
        bot_send_message(bot, chat_id, "Could not load markov chain: File has invalid format");
        return;
    }

    if (prompt_chat && sv_eq_cstr(command, "feed")) {
        snprintf(buf, 8192, SV_Fmt, SV_Arg(cmd));

        if (bot_feed_file(bot, buf) < 0) {
            snprintf(buf, 8192, "Could not open file "SV_Fmt": %s",
                     SV_Arg(cmd), strerror(errno));
            bot_send_message(bot, chat_id, buf);
        }
        return;
    }

    if ((chat_id > 0 && sv_eq_cstr(command, "/carrot"))
        || sv_eq_cstr(command, "/carrot@markov_m0x1m_bot")) {
        bot_carrot_command(ctx, chat_id, cmd);
        return;
    }

    if (bot->window[WINDOW_SIZE - 1] != ' ') bot_feed_code(bot, ' ');
    while (text.count) bot_feed_code(bot, sv_read_unicode(&text));
}

void async_bot_request_get_updates(bot_async_ctx *ctx)
{
    json_object *json = json_object_new_object();

    json_object_object_add(json, "timeout", json_object_new_int(600));
    ctx->pollable->timeout = 600 * 1000;
    if (ctx->bot->last_confirmed) {
        json_object_object_add(json, "offset", json_object_new_int(ctx->bot->last_confirmed + 1));
    }

    json_object *allowed_updates = json_object_new_array();
    json_object_array_add(allowed_updates, json_object_new_string("message"));
    json_object_object_add(json, "allowed_updates", allowed_updates);

    async_bot_telegram_post_method(ctx, "getUpdates", json);
    json_object_put(json);

    bio_flush(ctx->bio);

    int len = http_get_content_length(ctx);
    char *body_data = arena_alloc(&ctx->a, len);
    bio_read(ctx->bio, body_data, len);

    json_tokener *tokener = json_tokener_new();
    json_object *body = json_tokener_parse_ex(tokener, body_data, len);
    json_tokener_free(tokener);

    if (!body) return;

    json_object *updates = json_object_object_get(body, "result");
    if (!updates || !json_object_is_type(updates, json_type_array)) {
        json_object_put(body);
        return;
    }

    int updates_len = json_object_array_length(updates);

    for (int i = 0; i < updates_len; ++i) {
        json_object *update = json_object_array_get_idx(updates, i);

        json_object *message = json_object_object_get(update, "message");
        json_object *update_id = json_object_object_get(update, "update_id");
        ctx->bot->last_confirmed = json_object_get_int(update_id);

        json_object *json_text = json_object_object_get(message, "text");
        if (json_text == NULL) continue;

        string_view text;

        text.data = json_object_get_string(json_text);
        text.count = json_object_get_string_len(json_text);

        json_object *chat = json_object_object_get(message, "chat");
        int64_t chat_id = json_object_get_int64(json_object_object_get(chat, "id"));

        bot_handle_message(ctx, chat_id, text);
    }

    json_object_put(body);
}

struct bot_async_closure {
    bot_async_fn func;
    void *data;
    struct bot *bot;
};

void async_wrapper(struct pollable *this, void *data)
{
    struct bot_async_closure *closure = data;
    struct secure_fd fd;
    bot_async_ctx ctx = {0};

    ctx.pollable = this;
    ctx.bot = closure->bot;
    if (this->fd < 0) goto func;

    ctx.bio = malloc(sizeof *ctx.bio);

    fd.ssl = SSL_new(closure->bot->ssl_ctx);
    if (fd.ssl == NULL) goto done;
    SSL_set_fd(fd.ssl, this->fd);
    fd.pollable = this;

    if (setjmp(this->on_closed)) goto done;
    int ret;
    ASYNC_SSL(fd.ssl, (ret = SSL_connect(fd.ssl)), this);
    if (ret <= 0) goto done;

    bio_init(ctx.bio, &fd, secure_read, secure_write);

func:
    closure->func(&ctx, closure->data);

 done:
    free(closure);
    arena_free(&ctx.a);
    if (fd.ssl) SSL_free(fd.ssl);
    free(ctx.bio);

    if (ctx.pollable->fd >= 0) close(ctx.pollable->fd);
    ctx.pollable->finished = 1;

    co_switch(ctx.pollable->el->ctx);
}

void async_bot_event_listener(bot_async_ctx *ctx, void *data)
{
    (void) data;

    if (setjmp(ctx->pollable->on_closed)) goto end;

    for (;;) {
        async_bot_request_get_updates(ctx);
        arena_free(&ctx->a);
    }

 end:
    close(ctx->pollable->fd);
    ctx->pollable->fd = -1;
    while (bot_receive_events(ctx->bot) < 0) {
        ctx->pollable->timeout = 10000;
        ctx->pollable->flags = 0;
        co_switch(ctx->pollable->el->ctx);
    }
}

void async_bot_set_my_commands(bot_async_ctx *ctx, void *data)
{
    (void) data;

    json_object *json = json_object_new_object();
    json_object *commands = json_object_new_array();
    json_object *command = json_object_new_object();
    json_object_object_add(command, "command", json_object_new_string("carrot"));
    json_object_object_add(command, "description", json_object_new_string("Generates random text based on the chat history"));
    json_object_array_add(commands, command);
    json_object_object_add(json, "commands", commands);
    async_bot_telegram_post_method(ctx, "setMyCommands", json);
    json_object_put(json);

    bio_flush(ctx->bio);

    string_view body;

    body.count = http_get_content_length(ctx);
    body.data = arena_alloc(&ctx->a, body.count);
    bio_read(ctx->bio, (char *) body.data, body.count);
}

int bot_connect(void)
{
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    int host_addr = get_addr(HOST);
    if (host_addr == -1) return -1;
    addr.sin_addr.s_addr = host_addr;

    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

    if (sock < 0) {
        fprintf(stderr, "ERROR: could not create socket: %s\n", strerror(errno));
        abort();
    }

    int ret = connect(sock, (struct sockaddr *)&addr, sizeof addr);
    if (ret < 0 && errno != EINPROGRESS) {
        return -1;
    }

    return sock;
}

void bot_add_task(struct bot *bot, int fd, bot_async_fn func, void *func_data)
{
    struct bot_async_closure *closure = malloc(sizeof *closure);

    closure->bot = bot;
    closure->func = func;
    closure->data = func_data;

    event_loop_add(&bot->el, fd, POLLOUT, async_wrapper, closure);
}

int bot_add_net_task(struct bot *bot, bot_async_fn func, void *func_data)
{
    int fd = bot_connect();
    if (fd < 0) return -1;

    bot_add_task(bot, fd, func, func_data);

    return 0;
}

int bot_set_my_commands(struct bot *bot)
{
    return bot_add_net_task(bot, async_bot_set_my_commands, NULL);
}

int bot_receive_events(struct bot *bot)
{
    return bot_add_net_task(bot, async_bot_event_listener, NULL);
}

void bot_event_loop(struct bot *bot)
{
    while (bot->el.count) {
        event_loop_next(&bot->el);
    }
}

int bot_init(struct bot *bot)
{
    memset(bot, 0, sizeof *bot);

    bot->mc.compare = compare_prefixes;
    bot->mc.hashf = hashf_prefixes;

    bot->token = getenv("TOKEN");
    if (bot->token == NULL) {
        fprintf(stderr, "ERROR: TOKEN environment variable was not provided\n");
        return -1;
    }

    bot->ssl_ctx = SSL_CTX_new(TLS_client_method());
    RAND_bytes((void*) &bot->prompt_secret, sizeof bot->prompt_secret);
    printf("Prompt secret: %lu\n", bot->prompt_secret);
    bot->el.ctx = co_active();

    return 0;
}

int main(void)
{
    struct bot bot;
    if (bot_init(&bot) < 0) return 1;

    bot_set_my_commands(&bot);
    bot_receive_events(&bot);

    bot_event_loop(&bot);
    bot_save_markov(&bot);

    SSL_CTX_free(bot.ssl_ctx);
    return 0;
}
