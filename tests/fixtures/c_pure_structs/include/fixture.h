#ifndef FIXTURE_H
#define FIXTURE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct PointerChild {
    uint32_t id;
    uint32_t flags;
    uint32_t score;
    uint32_t samples[4];
    char label[16];
} PointerChild;

typedef struct PointerParent {
    uint32_t magic;
    size_t child_count;
    PointerChild *first;
    PointerChild *second;
    char label[24];
} PointerParent;

typedef struct InlineChild {
    uint32_t id;
    uint32_t flags;
    uint32_t score;
    uint32_t samples[4];
    char label[16];
} InlineChild;

typedef struct InlineParent {
    uint32_t magic;
    size_t child_count;
    InlineChild first;
    InlineChild second;
    char label[24];
} InlineParent;

typedef struct MixedChild {
    uint32_t id;
    uint32_t flags;
    uint32_t score;
    uint32_t samples[4];
    char label[16];
} MixedChild;

typedef struct MixedParent {
    uint32_t magic;
    size_t child_count;
    InlineChild inline_child;
    MixedChild *dynamic_child;
    PointerChild *pointer_child;
    char label[24];
} MixedParent;

int run_demo(void);

#ifdef __cplusplus
}
#endif

#endif /* FIXTURE_H */
