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

/* ------------------------------------------------------------------ */
/* Expanded fixture surface (2026-08): deeper nesting, arrays, lists,  */
/* function-pointer dispatch, globals — scan and child-scan targets.   */
/* ------------------------------------------------------------------ */

typedef struct Vec2s {
    int32_t x;
    int32_t y;
} Vec2s;

typedef struct GridCell {
    uint8_t occupancy;
    uint8_t terrain;
    uint16_t flags;
    Vec2s coord;
} GridCell;

typedef struct Grid {
    uint32_t width;
    uint32_t height;
    GridCell *cells;
} Grid;

typedef struct StringView {
    const char *data;
    size_t length;
} StringView;

typedef struct KeyValue {
    const char *key;
    const char *value;
    struct KeyValue *next;
} KeyValue;

typedef struct PropertyBag {
    KeyValue *head;
    size_t count;
} PropertyBag;

typedef struct DispatchCtx {
    void *userdata;
    uint32_t code;
} DispatchCtx;

typedef int (*DispatchFn)(void *state, uint32_t code);

typedef struct Dispatcher {
    DispatchFn handlers[6];
    void *states[6];
    uint32_t handler_count;
} Dispatcher;

typedef struct DeepChainNode {
    struct DeepChainNode *next;
    struct DeepChainNode *child;
    uint32_t tag;
    uint8_t payload[16];
} DeepChainNode;

typedef struct InnerRec {
    uint16_t a;
    uint16_t b;
    uint32_t c;
} InnerRec;

typedef struct Variant {
    uint32_t kind;
    union {
        uint32_t as_u32;
        int32_t as_i32;
        float as_f32;
        const void *as_ptr;
    } as;
} Variant;

typedef struct ItemStack {
    Variant meta;
    uint32_t count;
} ItemStack;

typedef struct Outer {
    uint64_t magic;
    InnerRec inner[3];
    char name[40];
    DeepChainNode *chain;
    PropertyBag bag;
    Grid grid;
    Dispatcher dispatch;
    ItemStack stacks[4];
    size_t payload_size;
} Outer;

/* global objects: global-reference scans resolve these from xrefs */
extern Outer g_main_outer;
extern Grid g_static_grid;
extern const char *g_label_table[4];
extern const char g_banner[];

/* additional entry points (kept exported so they stay in the binary) */
int run_nested_fixture(void);
int run_list_fixture(void);
int run_dispatch_fixture(void);
int run_array_fixture(void);
int run_recursive_chain_fixture(void);

#ifdef __cplusplus
}
#endif

#endif /* FIXTURE_H */
