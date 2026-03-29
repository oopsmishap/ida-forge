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
    puts("=== pure c structure fixture end ===");
    return 0;
}
