#include <stdint.h>
#include <assert.h>

#ifndef UTILS_H_
#define UTILS_H_

#ifndef UTILS_DEF
#define UTILS_DEF
#endif

#define ARRAY_LEN(xs) (sizeof(xs)/sizeof((xs)[0]))

struct common_hashmap;

#define da_alloc(da, c)                                                 \
    do {                                                                \
        while ((da)->count + (c) > (da)->capacity) {                    \
            (da)->capacity = (da)->capacity ? (da)->capacity * 2 : 1;   \
            if ((da)->count + (c) > (da)->capacity) continue;           \
            (da)->items = realloc((da)->items, (da)->capacity * sizeof((da)->items[0])); \
            assert((da)->items);                                        \
        }                                                               \
    } while (0)

#define da_append(da, x)                                                \
    do {                                                                \
        da_alloc(da, 1);                                                \
        (da)->items[(da)->count++] = x;                                 \
    } while (0)

#define da_append_many(da, xs, cnt)                                     \
    do {                                                                \
        da_alloc(da, (cnt));                                            \
        memcpy(&(da)->items[(da)->count], (xs), (cnt) * sizeof(*(da)->items)); \
        (da)->count += cnt;                                             \
    } while (0)

#define da_append_many2(da, xs, cnt, ator, realloc)                     \
    do {                                                                \
        da_alloc2(da, cnt, ator, realloc);                              \
        memcpy(&(da)->items[(da)->count], (xs), (cnt) * sizeof(*(da)->items)); \
        (da)->count += cnt;                                             \
    } while (0)

#define da_alloc2(da, c, ator, realloc)                                 \
    do {                                                                \
        size_t old_capacity = (da)->capacity;                           \
        while ((da)->count + (c) > (da)->capacity) {                    \
            (da)->capacity = (da)->capacity ? (da)->capacity * 2 : 1;   \
            if ((da)->count + (c) > (da)->capacity) continue;           \
            (da)->items = realloc(ator, (da)->items, old_capacity * sizeof((da)->items[0]), \
                                  (da)->capacity * sizeof((da)->items[0])); \
            assert((da)->items);                                        \
        }                                                               \
    } while (0)

#define da_append2(da, x, ator, realloc)                                \
    do {                                                                \
        da_alloc2(da, 1, ator, realloc);                                \
        (da)->items[(da)->count++] = x;                                 \
    } while (0)

#define return_defer(v) do { result = v; goto defer; } while (0)
#define shift(xs, count) shift_impl(&(xs), &(count))

#define hashmap_get(hm, key) hashmap_get__(hm, sizeof((hm)->items[0]), key)
#define hashmap_insert(hm, item) hashmap_insert__(hm, sizeof((hm)->items[0]), item)
#define mandatory_arg(name) mandatory_arg_impl(usage, name, &argv, &argc, program_name)

struct bytes_array {
    char *items;
    size_t off;
    size_t count;
    size_t capacity;
};

typedef struct {
    const char *data;
    size_t count;
} string_view;

typedef struct arena {
    size_t used;
    size_t capacity;
    char *data;
    struct arena *prev;
} arena;

#define ARENA_CAP (4*1024*1024)

enum tag_type {
    TAG_End,
    TAG_Byte,
    TAG_Short,
    TAG_Int,
    TAG_Long,
    TAG_Float,
    TAG_Double,
    TAG_Byte_Array,
    TAG_String,
    TAG_List,
    TAG_Compound,
    TAG_Int_Array,
    TAG_Long_Array
};

struct nbt_tag;
union tag_variant;

struct compound_tags {
    struct nbt_tag **items;
    size_t count;
    size_t capacity;
};

struct list_tags {
    enum tag_type type;
    union tag_variant *items;
    size_t count;
    size_t capacity;
};

struct long_array_tag {
    int64_t *items;
    size_t count;
    size_t capacity;
};

struct int_array_tag {
    int32_t *items;
    size_t count;
    size_t capacity;
};

union tag_variant {
    char tag_byte;
    short tag_short;
    int tag_int;
    int64_t tag_long;
    float tag_float;
    double tag_double;
    struct compound_tags tag_compound;
    struct bytes_array tag_byte_array;
    struct long_array_tag tag_long_array;
    struct int_array_tag tag_int_array;
    struct list_tags tag_list;
    string_view tag_string;
};

struct nbt_tag {
    enum tag_type type;
    string_view name;
    union tag_variant variant;
};

#define read_be2(wherep, c)                                             \
    do {                                                                \
        memcpy(wherep, bytes_array_shift(nbt, c), c);                   \
        change_endian(wherep, c);                                       \
    } while (0)

#define read_be(where) read_be2(&where, sizeof(where))

#ifndef UTILS_DISABLE_ZLIB
UTILS_DEF int uncompress_bytes(struct bytes_array compr, struct bytes_array *out);
#endif

UTILS_DEF char *mandatory_arg_impl(void (*usage)(char*), char *name, char ***argv, int *argc, char *program_name);
UTILS_DEF char *shift_impl(char ***xs, int *count);
UTILS_DEF int hashmap_have_index(const void *base, size_t index);
UTILS_DEF int hashmap_insert__(void *base, size_t item_size, void *item);
UTILS_DEF int sv_eq_cstr(string_view sv, const char *cstr);
UTILS_DEF string_view sv_from_cstr(const char *cstr);
UTILS_DEF string_view sv_from_bytes_array(const struct bytes_array *bytes);
UTILS_DEF struct nbt_tag *compound_find_tag(struct compound_tags *tags, const char *name);
UTILS_DEF struct nbt_tag *deserialize_nbt(struct bytes_array *nbt, arena *a);
UTILS_DEF struct nbt_tag *nbt_compound_find_tag(struct nbt_tag *root, const char *name);
UTILS_DEF uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed);
UTILS_DEF void *arena_alloc(arena *a, size_t n);
UTILS_DEF void *arena_realloc(arena *a, void *p, size_t old_size, size_t new_size);
UTILS_DEF void *bytes_array_shift(struct bytes_array *b, size_t n);
UTILS_DEF void *hashmap_get__(void *base, size_t item_size, void *key);
UTILS_DEF void arena_free(arena *a);
UTILS_DEF void change_endian(void *d, size_t n);
UTILS_DEF void hashmap_resize(struct common_hashmap *ch, size_t item_size);
UTILS_DEF void print_nbt(struct nbt_tag *tag, int level);

#ifdef UTILS_IMPLEMENTATION

#include <assert.h>
#include <zlib.h>
#include <stdlib.h>
#include <string.h>

UTILS_DEF string_view sv_from_bytes_array(const struct bytes_array *bytes)
{
    return (string_view) {
        .count = bytes->count - bytes->off,
        .data = bytes->items + bytes->off
    };
}

UTILS_DEF void *bytes_array_shift(struct bytes_array *b, size_t n)
{
    void *items = (char*)b->items + b->off;
    b->off += n;
    return items;
}

#ifndef UTILS_DISABLE_ZLIB
UTILS_DEF int uncompress_bytes(struct bytes_array compr, struct bytes_array *out)
{
    z_stream stream = {0};
    stream.next_in = (Bytef *)compr.items + compr.off;
    stream.avail_in = compr.count - compr.off;

    if (inflateInit(&stream) != Z_OK) {
        return 1;
    }

    for (;;) {
        if (stream.avail_out < 4096) {
            da_alloc(out, 4096);
            stream.next_out = (Bytef *) &out->items[out->count];
            out->count += 4096 - stream.avail_out;
            stream.avail_out += 4096;
        }
        int ret = inflate(&stream, Z_NO_FLUSH);
        if (ret == Z_STREAM_END) break;
        if (ret != Z_OK) return 1;
    }

    inflateEnd(&stream);
    out->count = stream.total_out;

    return 0;
}
#endif

UTILS_DEF char *mandatory_arg_impl(void (*usage)(char*), char *name, char ***argv, int *argc, char *program_name)
{
    char *arg = shift_impl(argv, argc);
    if (arg == NULL) {
        fprintf(stderr, "ERROR: %s was not provided\n", name);
        usage(program_name);
        exit(1);
    }
    return arg;
}

UTILS_DEF void change_endian(void *d, size_t n)
{
    char *data = d;
    size_t hs = n/2;
    for (size_t i = 0; i < hs; ++i) {
        char t = data[n - i - 1];
        data[n - i - 1] = data[i];
        data[i] = t;
    }
}

struct common_hashmap {
    void *items;
    uint8_t *bitmap;
    uint64_t (*hashf)(const void *);
    int (*compare)(const void *, const void *);
    size_t count;
    size_t capacity;
};

#define HASHMAP_CONFLICT_LIMIT 500
#define HASHMAP_INITIAL_CAP 32

UTILS_DEF void hashmap_resize(struct common_hashmap *ch, size_t item_size)
{
    struct common_hashmap old = *ch;
    memset(ch, 0, sizeof(*ch));
    ch->compare = old.compare;
    ch->hashf = old.hashf;
    ch->capacity = old.capacity ? old.capacity * 2 : HASHMAP_INITIAL_CAP;
    ch->items = malloc(item_size * ch->capacity);
    ch->bitmap = malloc((ch->capacity + 7)/8);
    memset(ch->bitmap, 0, (ch->capacity + 7)/8);

    for (size_t i = 0; i < old.capacity; ++i) {
        if (!hashmap_have_index(&old, i)) continue;

        hashmap_insert__(ch, item_size, (char*)old.items + item_size*i);
    }

    free(old.bitmap);
    free(old.items);
}

UTILS_DEF int hashmap_insert__(void *base, size_t item_size, void *item)
{
    struct common_hashmap *h = base;
    if (h->capacity == 0) {
    resize:
        hashmap_resize(h, item_size);
    }

    void *hitem = hashmap_get__(base, item_size, item);
    if (hitem) {
        memcpy(hitem, item, item_size);
        return 1;
    }

    uint64_t hash = h->hashf(item) % h->capacity;
    size_t limit = HASHMAP_CONFLICT_LIMIT;
    if (limit > h->capacity) limit = h->capacity;

    for (size_t i = 0;; i++) {
        if (!(h->bitmap[hash >> 3] & (1<<(hash&7)))) break;
        hash = (hash + 1) % h->capacity;
        if (i > limit) goto resize;
    }

    hitem = (char*)h->items + hash * item_size;
    memcpy(hitem, item, item_size);
    h->bitmap[hash >> 3] |= 1 << (hash & 7);
    h->count++;
    return 0;
}

UTILS_DEF int hashmap_have_index(const void *base, size_t index)
{
    const struct common_hashmap *h = base;

    return !!(h->bitmap[index >> 3] & (1 << (index & 7)));
}

UTILS_DEF void *hashmap_get__(void *base, size_t item_size, void *key)
{
    struct common_hashmap *h = base;

    if (h->capacity == 0) return NULL;
    uint64_t hash = h->hashf(key) % h->capacity;
    void *item;

    size_t limit = HASHMAP_CONFLICT_LIMIT;
    if (limit > h->capacity) limit = h->capacity;

    for (size_t i = 0; i < limit;
         i++, hash = (hash + 1) % h->capacity) {
        if (!hashmap_have_index(base, hash)) continue;
        item = (char*)h->items + item_size * hash;
        if (h->compare(key, item) == 0) return item;
    }

    return NULL;
}

UTILS_DEF char *shift_impl(char ***xs, int *count)
{
    if (*count) return --*count, *(*xs)++;
    else return NULL;
}

UTILS_DEF string_view sv_from_cstr(const char *cstr)
{
    return (string_view) {.data = cstr, .count = strlen(cstr)};
}

UTILS_DEF int sv_eq_cstr(string_view sv, const char *cstr)
{
    for (size_t i = 0; i < sv.count; ++i) {
        if (*cstr++ != sv.data[i]) return 0;
    }

    return *cstr == 0;
}

UTILS_DEF void *arena_alloc(arena *a, size_t n)
{
    n = (n + sizeof(void*) - 1) / sizeof(void*);
 again:
    if (a->capacity == 0) {
        a->data = malloc(ARENA_CAP);
        a->capacity = ARENA_CAP/sizeof(void*);
    }

    if (a->used + n >= a->capacity) {
        struct arena *prev;
        prev = malloc(sizeof(*a));
        *prev = *a;
        memset(a, 0, sizeof(*a));
        a->prev = prev;
        goto again;
    }

    void *p = a->data + a->used * sizeof(void *);
    a->used += n;
    return p;
}

UTILS_DEF void arena_free(arena *a)
{
    arena *prev = a->prev;
    free(a->data);
    memset(a, 0, sizeof *a);
    while (prev) {
        a = prev;
        prev = prev->prev;
        free(a->data);
        free(a);
    }
}

UTILS_DEF void *arena_realloc(arena *a, void *p, size_t old_size, size_t new_size)
{
    void *new = arena_alloc(a, new_size);
    memcpy(new, p, old_size);
    return new;
}

UTILS_DEF struct nbt_tag *compound_find_tag(struct compound_tags *tags, const char *name)
{
    for (size_t i = 0; i < tags->count; ++i) {
        if (sv_eq_cstr(tags->items[i]->name, name)) return tags->items[i];
    }

    return NULL;
}

UTILS_DEF struct nbt_tag *nbt_compound_find_tag(struct nbt_tag *root, const char *name)
{
    if (root->type != TAG_Compound) return NULL;
    struct compound_tags *tags = &root->variant.tag_compound;
    return compound_find_tag(tags, name);
}

static union tag_variant deserialize_tag_variant(enum tag_type type, struct bytes_array *nbt, arena *a)
{
    union tag_variant variant = {0};

    switch (type) {
    case TAG_Byte: {
        read_be(variant.tag_byte);
    } break;
    case TAG_Short: {
        read_be(variant.tag_short);
    } break;
    case TAG_Int: {
        read_be(variant.tag_int);
    } break;
    case TAG_Long: {
        read_be(variant.tag_long);
    } break;
    case TAG_String: {
        read_be2(&variant.tag_string.count, 2);
        variant.tag_string.data = bytes_array_shift(nbt, variant.tag_string.count);
    } break;
    case TAG_Float: {
        read_be(variant.tag_float);
    } break;
    case TAG_Double: {
        read_be(variant.tag_double);
    } break;
    case TAG_Long_Array: {
        int len;
        read_be(len);
        for (int i = 0; i < len; ++i) {
            int64_t val;
            read_be(val);
            da_append2(&variant.tag_long_array, val, a, arena_realloc);
        }
    } break;
    case TAG_Int_Array: {
        int len;
        read_be(len);
        for (int i = 0; i < len; ++i) {
            int32_t val;
            read_be(val);
            da_append2(&variant.tag_int_array, val, a, arena_realloc);
        }
    } break;
    case TAG_Byte_Array: {
        read_be2(&variant.tag_byte_array.count, sizeof(int));
        variant.tag_byte_array.items = bytes_array_shift(nbt, variant.tag_byte_array.count);
    } break;
    case TAG_Compound: {
        while (nbt->items[nbt->off] != TAG_End) {
            struct nbt_tag *tag = deserialize_nbt(nbt, a);
            da_append2(&variant.tag_compound, tag, a, arena_realloc);
        }
        bytes_array_shift(nbt, 1);
    } break;
    case TAG_List: {
        int len;
        char type;
        read_be(type);
        read_be(len);

        variant.tag_list.type = type;
        da_alloc2(&variant.tag_list, len, a, arena_realloc);
        variant.tag_list.count = len;

        for (int i = 0; i < len; ++i) {
            union tag_variant tag = deserialize_tag_variant(type, nbt, a);
            variant.tag_list.items[i] = tag;
        }
    } break;
    default: {
        printf("Tag %d is not implemented\n", type);
        assert(0);
    }
    }

    return variant;
}

UTILS_DEF struct nbt_tag *deserialize_nbt(struct bytes_array *nbt, arena *a)
{
    struct nbt_tag *tag = arena_alloc(a, sizeof(*tag));
    char type;
    read_be(type);
    uint16_t name_len;
    read_be(name_len);
    tag->type = type;
    tag->name.count = name_len;
    tag->name.data = bytes_array_shift(nbt, name_len);
    tag->variant = deserialize_tag_variant(tag->type, nbt, a);
    return tag;
}

UTILS_DEF struct nbt_tag *deserialize_net_nbt(struct bytes_array *nbt, arena *a)
{
    struct nbt_tag *tag = arena_alloc(a, sizeof(*tag));
    char type;
    read_be(type);
    tag->type = type;
    tag->name.count = 0;
    tag->variant = deserialize_tag_variant(tag->type, nbt, a);
    return tag;
}

static void print_tag_variant(enum tag_type type, union tag_variant *var, int level)
{
    switch (type) {
    case TAG_Byte: {
        printf("%d\n", var->tag_byte);
    } break;
    case TAG_Short: {
        printf("%d\n", var->tag_short);
    } break;
    case TAG_String: {
        printf("\"%.*s\"\n", (int) var->tag_string.count, var->tag_string.data);
    } break;
    case TAG_Int: {
        printf("%d\n", var->tag_int);
    } break;
    case TAG_Long: {
        printf("%ld\n", var->tag_long);
    } break;
    case TAG_Float: {
        printf("%f\n", var->tag_float);
    } break;
    case TAG_Double: {
        printf("%lf\n", var->tag_double);
    } break;
    case TAG_Byte_Array: {
        printf("u8[...]\n");
        if (0) for (size_t i = 0; i < var->tag_byte_array.count; ++i) {
            if (i % 16 == 0) printf("\n%*s", (level + 1) * 4, "");
            printf("%hhu, ", var->tag_byte_array.items[i]);
        }
        //printf("\n%*s]\n", level * 4, "");
    } break;
    case TAG_Long_Array: {
        printf("u64[...]\n");
        if (0) for (size_t i = 0; i < var->tag_long_array.count; ++i) {
            if (i % 16 == 0) printf("\n%*s", (level + 1) * 4, "");
            printf("%ld, ", var->tag_long_array.items[i]);
        }
        // printf("\n%*s]\n", level * 4, "");
    } break;
    case TAG_Int_Array: {
        printf("int[...]\n");
        if (0) for (size_t i = 0; i < var->tag_int_array.count; ++i) {
            if (i % 16 == 0) printf("\n%*s", (level + 1) * 4, "");
            printf("%d, ", var->tag_int_array.items[i]);
        }
        // printf("\n%*s]\n", level * 4, "");
    } break;
    case TAG_List: {
        printf("[\n");
        for (size_t i = 0; i < var->tag_list.count; ++i) {
            printf("%*s", (level + 1) * 4, "");
            print_tag_variant(var->tag_list.type, &var->tag_list.items[i], level + 1);
        }
        printf("%*s]\n", level * 4, "");
    } break;
    case TAG_Compound: {
        printf("{\n");
        for (size_t i = 0; i < var->tag_compound.count; ++i) {
            print_nbt(var->tag_compound.items[i], level + 1);
        }
        printf("%*s}\n", level * 4, "");
    } break;
    default: {
        fprintf(stderr, "Tag %d is not implemented\n", type);
        assert(0);
    }
    }
}

UTILS_DEF void print_nbt(struct nbt_tag *tag, int level)
{
    printf("%*s", level * 4, "");
    if (tag->name.count) printf("%.*s: ", (int) tag->name.count, tag->name.data);

    print_tag_variant(tag->type, &tag->variant, level);
}

static inline uint32_t murmur_32_scramble(uint32_t k)
{
    k *= 0xcc9e2d51;
    k = (k << 15) | (k >> 17);
    k *= 0x1b873593;
    return k;
}

UTILS_DEF uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed)
{
	uint32_t h = seed;
    uint32_t k;
    /* Read in groups of 4. */
    for (size_t i = len >> 2; i; i--) {
        // Here is a source of differing results across endiannesses.
        // A swap here has no effects on hash properties though.
        memcpy(&k, key, sizeof(uint32_t));
        key += sizeof(uint32_t);
        h ^= murmur_32_scramble(k);
        h = (h << 13) | (h >> 19);
        h = h * 5 + 0xe6546b64;
    }
    /* Read the rest. */
    k = 0;
    for (size_t i = len & 3; i; i--) {
        k <<= 8;
        k |= key[i - 1];
    }
    // A swap is *not* necessary here because the preceding loop already
    // places the low bytes in the low places according to whatever endianness
    // we use. Swaps only apply when the memory is copied in a chunk.
    h ^= murmur_32_scramble(k);
    /* Finalize. */
	h ^= len;
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return h;
}
#endif // UTILS_IMPLEMENTATION

#endif // UTILS_H_
