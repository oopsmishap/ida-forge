#include "fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void init_pointer_child(PointerChild *child, uint32_t id, const char *label, uint32_t base) {
    child->id = id;
    child->flags = base | 0x11U;
    child->score = base + 7U;
    child->samples[0] = base + 1U;
    child->samples[1] = base + 2U;
    child->samples[2] = base + 3U;
    child->samples[3] = base + 4U;
    snprintf(child->label, sizeof(child->label), "%s", label);
}

static void init_inline_child(InlineChild *child, uint32_t id, const char *label, uint32_t base) {
    child->id = id;
    child->flags = base | 0x22U;
    child->score = base + 9U;
    child->samples[0] = base + 5U;
    child->samples[1] = base + 6U;
    child->samples[2] = base + 7U;
    child->samples[3] = base + 8U;
    snprintf(child->label, sizeof(child->label), "%s", label);
}

static void init_mixed_child(MixedChild *child, uint32_t id, const char *label, uint32_t base) {
    child->id = id;
    child->flags = base | 0x33U;
    child->score = base + 11U;
    child->samples[0] = base + 9U;
    child->samples[1] = base + 10U;
    child->samples[2] = base + 11U;
    child->samples[3] = base + 12U;
    snprintf(child->label, sizeof(child->label), "%s", label);
}

static void dump_pointer_parent(const PointerParent *parent) {
    printf("[pointer] parent=%s magic=%08x count=%zu\n", parent->label, parent->magic, parent->child_count);
    printf("[pointer] first=%s id=%u flags=%u score=%u sample=%u\n", parent->first->label,
           parent->first->id, parent->first->flags, parent->first->score, parent->first->samples[2]);
    printf("[pointer] second=%s id=%u flags=%u score=%u sample=%u\n", parent->second->label,
           parent->second->id, parent->second->flags, parent->second->score, parent->second->samples[1]);
}

static void dump_inline_parent(const InlineParent *parent) {
    printf("[inline] parent=%s magic=%08x count=%zu\n", parent->label, parent->magic, parent->child_count);
    printf("[inline] first=%s id=%u flags=%u score=%u sample=%u\n", parent->first.label,
           parent->first.id, parent->first.flags, parent->first.score, parent->first.samples[0]);
    printf("[inline] second=%s id=%u flags=%u score=%u sample=%u\n", parent->second.label,
           parent->second.id, parent->second.flags, parent->second.score, parent->second.samples[3]);
}

static void dump_mixed_parent(const MixedParent *parent) {
    printf("[mixed] parent=%s magic=%08x count=%zu\n", parent->label, parent->magic, parent->child_count);
    printf("[mixed] inline=%s id=%u flags=%u score=%u sample=%u\n", parent->inline_child.label,
           parent->inline_child.id, parent->inline_child.flags, parent->inline_child.score,
           parent->inline_child.samples[1]);
    printf("[mixed] dynamic=%s id=%u flags=%u score=%u sample=%u\n", parent->dynamic_child->label,
           parent->dynamic_child->id, parent->dynamic_child->flags, parent->dynamic_child->score,
           parent->dynamic_child->samples[2]);
    printf("[mixed] pointer=%s id=%u flags=%u score=%u sample=%u\n", parent->pointer_child->label,
           parent->pointer_child->id, parent->pointer_child->flags, parent->pointer_child->score,
           parent->pointer_child->samples[0]);
}

static void run_pointer_parent_fixture(void) {
    PointerParent *parent = calloc(1, sizeof(*parent));
    PointerChild *first = calloc(1, sizeof(*first));
    PointerChild *second = calloc(1, sizeof(*second));
    if (parent == NULL || first == NULL || second == NULL) {
        puts("[pointer] allocation failed");
        free(parent);
        free(first);
        free(second);
        return;
    }

    parent->magic = 0x50545231U;
    parent->child_count = 2;
    parent->first = first;
    parent->second = second;
    snprintf(parent->label, sizeof(parent->label), "%s", "pointer_parent");

    init_pointer_child(first, 101U, "pointer_left", 0x10U);
    init_pointer_child(second, 102U, "pointer_right", 0x20U);

    printf("[pointer] parent=%p first=%p second=%p\n", (void *)parent, (void *)first, (void *)second);
    dump_pointer_parent(parent);

    free(second);
    free(first);
    free(parent);
}

static void run_inline_parent_fixture(void) {
    InlineParent *parent = calloc(1, sizeof(*parent));
    if (parent == NULL) {
        puts("[inline] allocation failed");
        return;
    }

    parent->magic = 0x494E4C31U;
    parent->child_count = 2;
    snprintf(parent->label, sizeof(parent->label), "%s", "inline_parent");

    init_inline_child(&parent->first, 201U, "inline_left", 0x30U);
    init_inline_child(&parent->second, 202U, "inline_right", 0x40U);

    printf("[inline] parent=%p first=%p second=%p\n", (void *)parent, (void *)&parent->first, (void *)&parent->second);
    dump_inline_parent(parent);

    free(parent);
}

static void run_mixed_parent_fixture(void) {
    MixedParent *parent = calloc(1, sizeof(*parent));
    MixedChild *dynamic_child = calloc(1, sizeof(*dynamic_child));
    PointerChild *pointer_child = calloc(1, sizeof(*pointer_child));
    if (parent == NULL || dynamic_child == NULL || pointer_child == NULL) {
        puts("[mixed] allocation failed");
        free(parent);
        free(dynamic_child);
        free(pointer_child);
        return;
    }

    parent->magic = 0x4D495831U;
    parent->child_count = 3;
    snprintf(parent->label, sizeof(parent->label), "%s", "mixed_parent");

    init_inline_child(&parent->inline_child, 301U, "mixed_inline", 0x50U);
    init_mixed_child(dynamic_child, 302U, "mixed_dynamic", 0x60U);
    init_pointer_child(pointer_child, 303U, "mixed_pointer", 0x70U);

    parent->dynamic_child = dynamic_child;
    parent->pointer_child = pointer_child;

    printf("[mixed] parent=%p inline=%p dynamic=%p pointer=%p\n", (void *)parent, (void *)&parent->inline_child,
           (void *)dynamic_child, (void *)pointer_child);
    dump_mixed_parent(parent);

    free(pointer_child);
    free(dynamic_child);
    free(parent);
}

int run_demo(void) {
    puts("=== pure c structure fixture begin ===");
    run_pointer_parent_fixture();
    run_inline_parent_fixture();
    run_mixed_parent_fixture();
    run_nested_fixture();
    run_list_fixture();
    run_dispatch_fixture();
    run_array_fixture();
    run_recursive_chain_fixture();
    puts("=== pure c structure fixture end ===");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Expanded fixture surface (2026-08):                                */
/*   run_nested_fixture      — Outer aggregate: arrays, chain, grid,  */
/*                             dispatcher, items, globals             */
/*   run_list_fixture        — PropertyBag linked list                */
/*   run_dispatch_fixture    — function-pointer handler array         */
/*   run_array_fixture       — heap grid + global label/banner refs   */
/*   run_recursive_chain_fixture — recursive tree walk                */
/* ------------------------------------------------------------------ */

Outer g_main_outer;
Grid g_static_grid;
const char *g_label_table[4] = {"alpha", "beta", "gamma", "delta"};
const char g_banner[] = "pure-c-struct-fixture";

static GridCell *build_grid(uint32_t width, uint32_t height) {
    GridCell *cells = calloc((size_t)width * height, sizeof(*cells));
    if (cells == NULL) {
        return NULL;
    }
    for (uint32_t y = 0; y < height; ++y) {
        for (uint32_t x = 0; x < width; ++x) {
            GridCell *cell = &cells[(size_t)y * width + x];
            cell->occupancy = (uint8_t)((x + y) % 8U);
            cell->terrain = (uint8_t)((x * 3U + y) % 5U);
            cell->flags = (uint16_t)(0x1000U + x * 0x101U + y);
            cell->coord.x = (int32_t)x * 16;
            cell->coord.y = (int32_t)y * 16;
        }
    }
    return cells;
}

static void destroy_grid(Grid *grid) {
    free(grid->cells);
    grid->cells = NULL;
    grid->width = 0;
    grid->height = 0;
}

static void kv_set(StringView *view, const char *text) {
    view->data = text;
    view->length = strlen(text);
}

static char *kv_dup(const char *text) {
    size_t len = strlen(text);
    char *copy = malloc(len + 1);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, text, len + 1);
    return copy;
}

static void kv_append(PropertyBag *bag, const char *key, const char *value) {
    KeyValue *entry = calloc(1, sizeof(*entry));
    if (entry == NULL) {
        return;
    }
    entry->key = kv_dup(key);
    entry->value = kv_dup(value);
    entry->next = NULL;
    if (bag->head == NULL) {
        bag->head = entry;
    } else {
        KeyValue *tail = bag->head;
        while (tail->next != NULL) {
            tail = tail->next;
        }
        tail->next = entry;
    }
    bag->count += 1;
}

static void build_property_bag(PropertyBag *bag) {
    kv_append(bag, "mode", "auto");
    kv_append(bag, "region", "north");
    kv_append(bag, "difficulty", "hard");
    kv_append(bag, "seed", "0xC0FFEE");
    kv_append(bag, "format", "binary");
}

static void destroy_property_bag(PropertyBag *bag) {
    KeyValue *entry = bag->head;
    while (entry != NULL) {
        KeyValue *next = entry->next;
        free((void *)entry->key);
        free((void *)entry->value);
        free(entry);
        entry = next;
    }
    bag->head = NULL;
    bag->count = 0;
}

static int on_echo_handler(void *state, uint32_t code) {
    const char *label = (const char *)state;
    printf("[dispatch] echo code=%08x state=%s\n", code, label);
    return (int)(code & 0xFFU);
}

static int on_store_handler(void *state, uint32_t code) {
    uint32_t *slot = (uint32_t *)state;
    *slot = code;
    printf("[dispatch] store %08x -> %p\n", code, (void *)slot);
    return 0;
}

static int on_guard_handler(void *state, uint32_t code) {
    const DispatchCtx *ctx = (const DispatchCtx *)state;
    printf("[dispatch] guard code=%08x userdata=%p\n", code, ctx->userdata);
    return (int)ctx->code;
}

static void init_dispatcher(Dispatcher *dispatcher) {
    static uint32_t stored_slot = 0;
    static DispatchCtx guard_ctx = {NULL, 0x51515151U};

    dispatcher->handlers[0] = on_echo_handler;
    dispatcher->states[0] = (void *)"dispatch-echo";
    dispatcher->handlers[1] = on_store_handler;
    dispatcher->states[1] = &stored_slot;
    dispatcher->handlers[2] = on_guard_handler;
    dispatcher->states[2] = &guard_ctx;
    dispatcher->handlers[3] = on_echo_handler;
    dispatcher->states[3] = (void *)"dispatch-mirror";
    dispatcher->handlers[4] = on_store_handler;
    dispatcher->states[4] = &stored_slot;
    dispatcher->handlers[5] = on_guard_handler;
    dispatcher->states[5] = &guard_ctx;
    dispatcher->handler_count = 6;
}

static DeepChainNode *make_chain(uint32_t depth, uint32_t children) {
    DeepChainNode *node = calloc(1, sizeof(*node));
    if (node == NULL) {
        return NULL;
    }
    node->tag = 0x1000U + depth * 0x100U;
    for (uint32_t i = 0; i < sizeof(node->payload); ++i) {
        node->payload[i] = (uint8_t)(depth * 3U + i);
    }
    if (depth > 0) {
        node->child = make_chain(depth - 1, children);
        for (uint32_t i = 1; i < children; ++i) {
            DeepChainNode *sibling = make_chain(depth - 1, children);
            if (node->next == NULL) {
                node->next = sibling;
            } else {
                DeepChainNode *tail = node->next;
                while (tail->next != NULL) {
                    tail = tail->next;
                }
                tail->next = sibling;
            }
        }
    }
    return node;
}

static void destroy_chain(DeepChainNode *node) {
    while (node != NULL) {
        DeepChainNode *next = node->next;
        destroy_chain(node->child);
        free(node);
        node = next;
    }
}

static uint32_t walk_chain_sum(const DeepChainNode *node) {
    uint32_t sum = 0;
    while (node != NULL) {
        sum += node->tag;
        for (uint32_t i = 0; i < sizeof(node->payload); ++i) {
            sum += node->payload[i];
        }
        sum += walk_chain_sum(node->child);
        node = node->next;
    }
    return sum;
}

static void fill_outer(Outer *outer) {
    outer->magic = 0x4F555445U;
    for (uint32_t i = 0; i < 3; ++i) {
        outer->inner[i].a = (uint16_t)(0x10U + i);
        outer->inner[i].b = (uint16_t)(0x20U + i);
        outer->inner[i].c = 0x300U + i;
    }
    snprintf(outer->name, sizeof(outer->name), "%s", "outer_aggregate");
    outer->bag.head = NULL;
    outer->bag.count = 0;
    outer->grid.width = 0;
    outer->grid.height = 0;
    outer->grid.cells = NULL;
    outer->chain = NULL;
    outer->dispatch.handler_count = 0;
    for (uint32_t i = 0; i < 4; ++i) {
        outer->stacks[i].meta.kind = i;
        outer->stacks[i].meta.as.as_u32 = 0x4000U + i;
        outer->stacks[i].count = 1U + i;
    }
    outer->payload_size = sizeof(outer->inner);
    init_dispatcher(&outer->dispatch);
    outer->chain = make_chain(2, 3);
    outer->grid.cells = build_grid(3, 3);
    outer->grid.width = 3;
    outer->grid.height = 3;
}

static size_t serialize_outer(const Outer *outer, char *buf, size_t cap) {
    size_t written = 0;
    int n = snprintf(
        buf, cap, "OUTER name=%s magic=%08x chainsum=%u cells=%ux%u",
        outer->name,
        (unsigned)outer->magic,
        walk_chain_sum(outer->chain),
        outer->grid.width,
        outer->grid.height);
    if (n < 0) {
        return 0;
    }
    written = (size_t)n;
    if (written >= cap) {
        return 0;
    }
    return written;
}

int run_nested_fixture(void) {
    Outer *outer = &g_main_outer;
    memset(outer, 0, sizeof(*outer));
    fill_outer(outer);

    printf("[nested] outer=%s magic=%08x grids=%ux%u chainsum=%u\n",
           outer->name, (unsigned)outer->magic,
           outer->grid.width, outer->grid.height,
           walk_chain_sum(outer->chain));
    printf("[nested] inner0={a=%u b=%u c=%u}\n", outer->inner[0].a,
           outer->inner[0].b, outer->inner[0].c);
    printf("[nested] stack2={kind=%u u=%08x count=%u}\n",
           outer->stacks[2].meta.kind, outer->stacks[2].meta.as.as_u32,
           outer->stacks[2].count);

    char serialized[512];
    size_t n = serialize_outer(outer, serialized, sizeof(serialized));
    if (n > 0) {
        printf("[nested] serialized=%s\n", serialized);
    }

    destroy_chain(outer->chain);
    outer->chain = NULL;
    destroy_grid(&outer->grid);
    return (int)(n & 0xFFU);
}

int run_list_fixture(void) {
    PropertyBag bag;
    memset(&bag, 0, sizeof(bag));
    build_property_bag(&bag);

    printf("[list] keys=%zu\n", bag.count);
    for (const KeyValue *entry = bag.head; entry != NULL; entry = entry->next) {
        StringView key;
        StringView value;
        kv_set(&key, entry->key);
        kv_set(&value, entry->value);
        printf("[list] %s=%s\n", key.data, value.data);
    }
    destroy_property_bag(&bag);
    return 0;
}

int run_dispatch_fixture(void) {
    Dispatcher dispatcher;
    memset(&dispatcher, 0, sizeof(dispatcher));
    init_dispatcher(&dispatcher);

    printf("[dispatch] handlers=%u\n", dispatcher.handler_count);
    int status = 0;
    for (uint32_t i = 0; i < dispatcher.handler_count; ++i) {
        status += dispatcher.handlers[i](dispatcher.states[i], 0x100U + i);
    }
    return status & 0xFF;
}

int run_array_fixture(void) {
    g_static_grid.width = 4;
    g_static_grid.height = 4;
    g_static_grid.cells = build_grid(g_static_grid.width, g_static_grid.height);
    if (g_static_grid.cells == NULL) {
        printf("[array] allocation failed\n");
        return 1;
    }

    printf("[array] banner=%s grid=%ux%u\n", g_banner,
           g_static_grid.width, g_static_grid.height);
    const GridCell *corner = &g_static_grid.cells[0];
    printf("[array] corner flags=%04x terrain=%u\n", corner->flags, corner->terrain);
    printf("[array] label[2]=%s\n", g_label_table[2]);
    g_static_grid.cells[g_static_grid.width - 1].coord.y = 4096;

    destroy_grid(&g_static_grid);
    return 0;
}

int run_recursive_chain_fixture(void) {
    DeepChainNode *root = make_chain(3, 2);
    if (root == NULL) {
        printf("[chain] allocation failed\n");
        return 1;
    }

    uint32_t sum = walk_chain_sum(root);
    printf("[chain] root tag=%08x payload[1]=%u sum=%u\n",
           root->tag, root->payload[1], sum);
    printf("[chain] child tag=%08x\n", root->child != NULL ? root->child->tag : 0U);
    printf("[chain] next tag=%08x\n", root->next != NULL ? root->next->tag : 0U);

    destroy_chain(root);
    return (int)(sum & 0xFFU);
}
