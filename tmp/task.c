/* Coroutine scheduler */

#include <stdatomic.h>
#include <stdbool.h>

#include "task.h"

#ifndef TASK_EXTERN
#define TASK_EXTERN
#endif

#include <stdbool.h>
#include <stddef.h>
#define LLCO_MINSTACKSIZE 16384
struct coro_desc {
    void *stack;
    size_t stack_size;
    void (*entry)(void *udata);
    void (*cleanup)(void *stack, size_t stack_size, void *udata);
    void *udata;
};

#include <stdlib.h>

#if defined(__GNUC__) || defined(__clang__)
#define __NOINLINE __attribute__((noinline))
#define __NORETURN __attribute__((noreturn))
#else
#define __NOINLINE
#define __NORETURN
#endif

static void coro_entry(void *arg);

__NORETURN
static void coro_exit(void)
{
    _Exit(0);
}

/* x86-64 */
#if defined(__x86_64__)

struct coro_asmctx {
    void *rip, *rsp, *rbp, *rbx, *r12, *r13, *r14, *r15;
};

void _coro_asm_entry(void);
int _coro_asm_switch(struct coro_asmctx *from, struct coro_asmctx *to);

__asm__(
    ".text\n"
#ifdef __APPLE__
    ".globl __coro_asm_entry\n"
    "__coro_asm_entry:\n"
#else /* Linux assumed */
    ".globl _coro_asm_entry\n"
    ".type _coro_asm_entry @function\n"
    ".hidden _coro_asm_entry\n"
    "_coro_asm_entry:\n"
#endif
    "  movq %r13, %rdi\n"
    "  jmpq *%r12\n"
#ifndef __APPLE__
    ".size _coro_asm_entry, .-_coro_asm_entry\n"
#endif
);

__asm__(
    ".text\n"
#ifdef __APPLE__
    ".globl __coro_asm_switch\n"
    "__coro_asm_switch:\n"
#else /* Linux assumed */
    ".globl _coro_asm_switch\n"
    ".type _coro_asm_switch @function\n"
    ".hidden _coro_asm_switch\n"
    "_coro_asm_switch:\n"
#endif
    "  leaq 0x3d(%rip), %rax\n"
    "  movq %rax, (%rdi)\n"
    "  movq %rsp, 8(%rdi)\n"
    "  movq %rbp, 16(%rdi)\n"
    "  movq %rbx, 24(%rdi)\n"
    "  movq %r12, 32(%rdi)\n"
    "  movq %r13, 40(%rdi)\n"
    "  movq %r14, 48(%rdi)\n"
    "  movq %r15, 56(%rdi)\n"
    "  movq 56(%rsi), %r15\n"
    "  movq 48(%rsi), %r14\n"
    "  movq 40(%rsi), %r13\n"
    "  movq 32(%rsi), %r12\n"
    "  movq 24(%rsi), %rbx\n"
    "  movq 16(%rsi), %rbp\n"
    "  movq 8(%rsi), %rsp\n"
    "  jmpq *(%rsi)\n"
    "  ret\n"
#ifndef __APPLE__
    ".size _coro_asm_switch, .-_coro_asm_switch\n"
#endif
);

static void coro_asmctx_make(struct coro_asmctx *ctx,
                             void *stack_base,
                             size_t stack_size,
                             void *arg)
{
    /* Reserve 128 bytes for the Red Zone space (System V AMD64 ABI). */
    stack_size = stack_size - 128;
    void **stack_high_ptr =
        (void **) ((size_t) stack_base + stack_size - sizeof(size_t));
    stack_high_ptr[0] =
        (void *) (0xdeaddeaddeaddead); /* Dummy return address */
    ctx->rip = (void *) (_coro_asm_entry);
    ctx->rsp = (void *) (stack_high_ptr);
    ctx->r12 = (void *) (coro_entry);
    ctx->r13 = (void *) (arg);
}

#else
#error Unsupported architecture.
#endif /* x86-64 only */

/* low-level coroutine switching */

struct coro {
    struct coro_desc desc;
    struct coro_asmctx ctx;
};

static __thread struct coro coro_thread = {0};
static __thread struct coro *coro_cur = NULL;
static __thread struct coro_desc coro_desc;
static __thread volatile bool coro_cleanup_needed = false;
static __thread volatile struct coro_desc coro_cleanup_desc;
static __thread volatile bool coro_cleanup_active = false;

#include <stdio.h>

#define coro_cleanup_guard()                                                \
    {                                                                       \
        if (coro_cleanup_active) {                                          \
            fprintf(stderr, "%s not available during cleanup\n", __func__); \
            abort();                                                        \
        }                                                                   \
    }

static void coro_cleanup_last(void)
{
    if (coro_cleanup_needed) {
        if (coro_cleanup_desc.cleanup) {
            coro_cleanup_active = true;
            coro_cleanup_desc.cleanup(coro_cleanup_desc.stack,
                                      coro_cleanup_desc.stack_size,
                                      coro_cleanup_desc.udata);
            coro_cleanup_active = false;
        }
        coro_cleanup_needed = false;
    }
}

__NOINLINE
static void coro_entry_wrap(void *arg)
{
    coro_cleanup_last();
    (void) arg;
    struct coro self = {.desc = coro_desc};
    coro_cur = &self;
    coro_cur->desc.entry(coro_cur->desc.udata);
}

__NOINLINE __NORETURN static void coro_entry(void *arg)
{
    coro_entry_wrap(arg);
    coro_exit();
}

__NOINLINE
static void coro_switch1(struct coro *from,
                         struct coro *to,
                         void *stack,
                         size_t stack_size)
{
    if (to) {
        _coro_asm_switch(&from->ctx, &to->ctx);
    } else {
        struct coro_asmctx ctx = {0};
        coro_asmctx_make(&ctx, stack, stack_size, 0);
        _coro_asm_switch(&from->ctx, &ctx);
    }
}

static void coro_switch0(struct coro_desc *desc, struct coro *co, bool final)
{
    struct coro *from = coro_cur ? coro_cur : &coro_thread;
    struct coro *to = desc ? NULL : co ? co : &coro_thread;
    if (from != to) {
        if (final) {
            coro_cleanup_needed = true;
            coro_cleanup_desc = from->desc;
        }
        if (desc) {
            coro_desc = *desc;
            coro_switch1(from, 0, desc->stack, desc->stack_size);
        } else {
            coro_cur = to;
            coro_switch1(from, to, 0, 0);
        }
        coro_cleanup_last();
    }
}

/* Start a new coroutine */
void coro_start(struct coro_desc *desc, bool final)
{
    if (!desc || desc->stack_size < LLCO_MINSTACKSIZE) {
        fprintf(stderr, "stack too small\n");
        abort();
    }
    coro_cleanup_guard();
    coro_switch0(desc, 0, final);
}

/* Switch to another coroutine */
void coro_switch(struct coro *co, bool final)
{
    /* fast track context switch. Saves a few nanoseconds by checking the
     * exception condition first.
     */
    if (!coro_cleanup_active && coro_cur && co && coro_cur != co && !final) {
        struct coro *from = coro_cur;
        coro_cur = co;
        _coro_asm_switch(&from->ctx, &co->ctx);
        coro_cleanup_last();
        return;
    }
    coro_cleanup_guard();
    coro_switch0(0, co, final);
}

/* Return the current coroutine or NULL if not currently running in a coroutine.
 */
struct coro *coro_current(void)
{
    coro_cleanup_guard();
    return coro_cur == &coro_thread ? 0 : coro_cur;
}

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__linux__)
#include <sched.h>
static void sched_yield0(void)
{
    sched_yield();
}
#else
#define sched_yield0()
#endif

/* Generate AA Tree.
 * See https://en.wikipedia.org/wiki/AA_tree
 */

#define AAT_DEF(specifiers, prefix, type)                      \
    specifiers type *prefix##_insert(type **root, type *item); \
    specifiers type *prefix##_delete(type **root, type *key);

#define AAT_FIELDS(type, left, right, level) \
    type *left;                              \
    type *right;                             \
    int level;

#define AAT_IMPL(prefix, type, left, right, level, compare)                   \
    static void prefix##_clear(type *node)                                    \
    {                                                                         \
        if (node) {                                                           \
            node->left = 0;                                                   \
            node->right = 0;                                                  \
            node->level = 0;                                                  \
        }                                                                     \
    }                                                                         \
                                                                              \
    static type *prefix##_skew(type *node)                                    \
    {                                                                         \
        if (node && node->left && node->left->level == node->level) {         \
            type *left_node = node->left;                                     \
            node->left = left_node->right;                                    \
            left_node->right = node;                                          \
            node = left_node;                                                 \
        }                                                                     \
        return node;                                                          \
    }                                                                         \
                                                                              \
    static type *prefix##_split(type *node)                                   \
    {                                                                         \
        if (node && node->right && node->right->right &&                      \
            node->right->right->level == node->level) {                       \
            type *right_node = node->right;                                   \
            node->right = right_node->left;                                   \
            right_node->left = node;                                          \
            right_node->level++;                                              \
            node = right_node;                                                \
        }                                                                     \
        return node;                                                          \
    }                                                                         \
                                                                              \
    static type *prefix##_insert0(type *node, type *item, type **replaced)    \
    {                                                                         \
        if (!node) {                                                          \
            item->left = 0;                                                   \
            item->right = 0;                                                  \
            item->level = 1;                                                  \
            node = item;                                                      \
        } else {                                                              \
            int cmp = compare(item, node);                                    \
            if (cmp < 0) {                                                    \
                node->left = prefix##_insert0(node->left, item, replaced);    \
            } else if (cmp > 0) {                                             \
                node->right = prefix##_insert0(node->right, item, replaced);  \
            } else {                                                          \
                *replaced = node;                                             \
                item->left = node->left;                                      \
                item->right = node->right;                                    \
                item->level = node->level;                                    \
                node = item;                                                  \
            }                                                                 \
        }                                                                     \
        node = prefix##_skew(node);                                           \
        node = prefix##_split(node);                                          \
        return node;                                                          \
    }                                                                         \
                                                                              \
    type *prefix##_insert(type **root, type *item)                            \
    {                                                                         \
        type *replaced = 0;                                                   \
        *root = prefix##_insert0(*root, item, &replaced);                     \
        if (replaced != item) {                                               \
            prefix##_clear(replaced);                                         \
        }                                                                     \
        return replaced;                                                      \
    }                                                                         \
                                                                              \
    static type *prefix##_decrease_level(type *node)                          \
    {                                                                         \
        if (node->left || node->right) {                                      \
            int new_level = 0;                                                \
            if (node->left && node->right) {                                  \
                if (node->left->level < node->right->level) {                 \
                    new_level = node->left->level;                            \
                } else {                                                      \
                    new_level = node->right->level;                           \
                }                                                             \
            }                                                                 \
            new_level++;                                                      \
            if (new_level < node->level) {                                    \
                node->level = new_level;                                      \
                if (node->right && new_level < node->right->level) {          \
                    node->right->level = new_level;                           \
                }                                                             \
            }                                                                 \
        }                                                                     \
        return node;                                                          \
    }                                                                         \
                                                                              \
    static type *prefix##_delete_fixup(type *node)                            \
    {                                                                         \
        node = prefix##_decrease_level(node);                                 \
        node = prefix##_skew(node);                                           \
        node->right = prefix##_skew(node->right);                             \
        if (node->right && node->right->right) {                              \
            node->right->right = prefix##_skew(node->right->right);           \
        }                                                                     \
        node = prefix##_split(node);                                          \
        node->right = prefix##_split(node->right);                            \
        return node;                                                          \
    }                                                                         \
                                                                              \
    static type *prefix##_delete_first0(type *node, type **deleted)           \
    {                                                                         \
        if (node) {                                                           \
            if (!node->left) {                                                \
                *deleted = node;                                              \
                if (node->right) {                                            \
                    node = node->right;                                       \
                } else {                                                      \
                    node = 0;                                                 \
                }                                                             \
            } else {                                                          \
                node->left = prefix##_delete_first0(node->left, deleted);     \
                node = prefix##_delete_fixup(node);                           \
            }                                                                 \
        }                                                                     \
        return node;                                                          \
    }                                                                         \
                                                                              \
    static type *prefix##_delete_last0(type *node, type **deleted)            \
    {                                                                         \
        if (node) {                                                           \
            if (!node->right) {                                               \
                *deleted = node;                                              \
                if (node->left) {                                             \
                    node = node->left;                                        \
                } else {                                                      \
                    node = 0;                                                 \
                }                                                             \
            } else {                                                          \
                node->right = prefix##_delete_last0(node->right, deleted);    \
                node = prefix##_delete_fixup(node);                           \
            }                                                                 \
        }                                                                     \
        return node;                                                          \
    }                                                                         \
                                                                              \
    static type *prefix##_delete0(type *node, type *key, type **deleted)      \
    {                                                                         \
        if (node) {                                                           \
            int cmp = compare(key, node);                                     \
            if (cmp < 0) {                                                    \
                node->left = prefix##_delete0(node->left, key, deleted);      \
            } else if (cmp > 0) {                                             \
                node->right = prefix##_delete0(node->right, key, deleted);    \
            } else {                                                          \
                *deleted = node;                                              \
                if (!node->left && !node->right) {                            \
                    node = 0;                                                 \
                } else {                                                      \
                    type *leaf_deleted = 0;                                   \
                    if (!node->left) {                                        \
                        node->right = prefix##_delete_first0(node->right,     \
                                                             &leaf_deleted);  \
                    } else {                                                  \
                        node->left =                                          \
                            prefix##_delete_last0(node->left, &leaf_deleted); \
                    }                                                         \
                    leaf_deleted->left = node->left;                          \
                    leaf_deleted->right = node->right;                        \
                    leaf_deleted->level = node->level;                        \
                    node = leaf_deleted;                                      \
                }                                                             \
            }                                                                 \
            if (node) {                                                       \
                node = prefix##_delete_fixup(node);                           \
            }                                                                 \
        }                                                                     \
        return node;                                                          \
    }                                                                         \
                                                                              \
    type *prefix##_delete(type **root, type *key)                             \
    {                                                                         \
        type *deleted = 0;                                                    \
        *root = prefix##_delete0(*root, key, &deleted);                       \
        prefix##_clear(deleted);                                              \
        return deleted;                                                       \
    }

/* Platform independent code below */

struct task_link {
    struct task *prev, *next;
};

struct task {
    union {
        /* Linked list */
        struct {
            struct task *prev, *next;
        };
        /* Binary tree (AA tree) */
        struct {
            AAT_FIELDS(struct task, left, right, level)
        };
    };
    int64_t id;
    void *udata;
    struct coro *llco;
};

static int task_compare(struct task *a, struct task *b)
{
    return a->id < b->id ? -1 : a->id > b->id;
}

AAT_DEF(static, task_aat, struct task)
AAT_IMPL(task_aat, struct task, left, right, level, task_compare)

/* https://zimbry.blogspot.com/2011/09/better-bit-mixing-improving-on.html
 * hash u64 using mix13
 */
static uint64_t task_mix13(uint64_t key)
{
    key ^= (key >> 30);
    key *= UINT64_C(0xbf58476d1ce4e5b9);
    key ^= (key >> 27);
    key *= UINT64_C(0x94d049bb133111eb);
    key ^= (key >> 31);
    return key;
}

/* task_map - A hashmap-style structure that stores task types using multiple
 * binary search trees (aa-tree) in hashed shards. This allows for the map to
 * grow evenly, without allocations, and performing much faster than using a
 * single BST.
 */

#ifndef TASK_N_SHARDS
#define TASK_N_SHARDS 512
#endif

struct task_map {
    struct task *roots[TASK_N_SHARDS];
    int count;
};

#define scp_map_getaat(task) \
    (&map->roots[task_mix13((task)->id) & (TASK_N_SHARDS - 1)])

static struct task *task_map_insert(struct task_map *map, struct task *task)
{
    struct task *prev = task_aat_insert(scp_map_getaat(task), task);
    if (!prev)
        map->count++;
    return prev;
}

static struct task *task_map_delete(struct task_map *map, struct task *key)
{
    struct task *prev = task_aat_delete(scp_map_getaat(key), key);
    if (prev)
        map->count--;
    return prev;
}

struct task_list {
    struct task_link head, tail;
};

/* Global and thread-local variables. */

static __thread bool task_initialized = false;
static __thread size_t task_nrunners = 0;
static __thread struct task_list task_runners = {0};
static __thread size_t task_nyielders = 0;
static __thread struct task_list task_yielders = {0};
static __thread struct task *task_cur = NULL;
static __thread struct task_map task_paused = {0};
static __thread size_t task_npaused = 0;
static __thread bool task_exit_to_main_requested = false;
static __thread void (*task_user_entry)(void *udata);

static atomic_int_fast64_t task_next_id = 0;
static atomic_bool task_locker = 0;
static struct task_map task_detached = {0};
static size_t task_ndetached = 0;

static void task_lock(void)
{
    bool expected = false;
    while (!atomic_compare_exchange_weak(&task_locker, &expected, true)) {
        expected = false;
        sched_yield0();
    }
}

static void task_unlock(void)
{
    atomic_store(&task_locker, false);
}

static void task_list_init(struct task_list *list)
{
    list->head.prev = NULL;
    list->head.next = (struct task *) &list->tail;
    list->tail.prev = (struct task *) &list->head;
    list->tail.next = NULL;
}

/* Remove the coroutine from the runners or yielders list. */
static void task_remove_from_list(struct task *co)
{
    co->prev->next = co->next;
    co->next->prev = co->prev;
    co->next = co;
    co->prev = co;
}

static void task_init(void)
{
    if (!task_initialized) {
        task_list_init(&task_runners);
        task_list_init(&task_yielders);
        task_initialized = true;
    }
}

static struct task *task_list_pop_front(struct task_list *list)
{
    struct task *co = NULL;
    if (list->head.next != (struct task *) &list->tail) {
        co = list->head.next;
        task_remove_from_list(co);
    }
    return co;
}

static void task_list_push_back(struct task_list *list, struct task *co)
{
    task_remove_from_list(co);
    list->tail.prev->next = co;
    co->prev = list->tail.prev;
    co->next = (struct task *) &list->tail;
    list->tail.prev = co;
}

static void task_return_to_main(bool final)
{
    task_cur = NULL;
    task_exit_to_main_requested = false;
    coro_switch(0, final);
}

static void task_switch(bool resumed_from_main, bool final)
{
    if (task_nrunners == 0) {
        /* No more runners */
        if (task_nyielders == 0 || task_exit_to_main_requested ||
            (!resumed_from_main && task_npaused > 0)) {
            task_return_to_main(final);
            return;
        }
        /* Convert the yielders to runners */
        task_runners.head.next = task_yielders.head.next;
        task_runners.head.next->prev = (struct task *) &task_runners.head;
        task_runners.tail.prev = task_yielders.tail.prev;
        task_runners.tail.prev->next = (struct task *) &task_runners.tail;
        task_yielders.head.next = (struct task *) &task_yielders.tail;
        task_yielders.tail.prev = (struct task *) &task_yielders.head;
        task_nrunners = task_nyielders;
        task_nyielders = 0;
    }
    task_cur = task_list_pop_front(&task_runners);
    task_nrunners--;
    coro_switch(task_cur->llco, final);
}

static void task_entry(void *udata)
{
    /* Initialize a new coroutine on the user's stack. */
    struct task task_stk = {0};
    struct task *co = &task_stk;
    co->llco = coro_current();
    co->id = atomic_fetch_add(&task_next_id, 1) + 1;
    co->udata = udata;
    co->prev = co;
    co->next = co;
    if (task_cur) {
        /* Reschedule the coroutine that started this one */
        task_list_push_back(&task_yielders, co);
        task_list_push_back(&task_yielders, task_cur);
        task_nyielders += 2;
        task_switch(false, false);
    }
    task_cur = co;
    if (task_user_entry) {
        task_user_entry(udata);
    }
    /* This coroutine is finished. Switch to the next coroutine. */
    task_switch(false, true);
}

TASK_EXTERN
void task_exit(void)
{
    if (task_cur) {
        task_exit_to_main_requested = true;
        task_switch(false, true);
    }
}

TASK_EXTERN
void task_start(struct task_desc *desc)
{
    task_init();
    struct coro_desc coro_desc = {
        .entry = task_entry,
        .cleanup = desc->cleanup,
        .stack = desc->stack,
        .stack_size = desc->stack_size,
        .udata = desc->udata,
    };
    task_user_entry = desc->entry;
    coro_start(&coro_desc, false);
}

TASK_EXTERN
int64_t task_id(void)
{
    return task_cur ? task_cur->id : 0;
}

TASK_EXTERN
void task_yield(void)
{
    if (task_cur) {
        task_list_push_back(&task_yielders, task_cur);
        task_nyielders++;
        task_switch(false, false);
    }
}

TASK_EXTERN
void task_pause(void)
{
    if (task_cur) {
        task_map_insert(&task_paused, task_cur);
        task_npaused++;
        task_switch(false, false);
    }
}

TASK_EXTERN
void task_resume(int64_t id)
{
    task_init();
    if (id == 0 && !task_cur) {
        /* Resuming from main */
        task_switch(true, false);
    } else {
        /* Resuming from coroutine */
        struct task *co =
            task_map_delete(&task_paused, &(struct task){.id = id});
        if (co) {
            task_npaused--;
            co->prev = co;
            co->next = co;
            task_list_push_back(&task_yielders, co);
            task_nyielders++;
            task_yield();
        }
    }
}

TASK_EXTERN
void task_detach(int64_t id)
{
    struct task *co = task_map_delete(&task_paused, &(struct task){.id = id});
    if (co) {
        task_npaused--;
        task_lock();
        task_map_insert(&task_detached, co);
        task_ndetached++;
        task_unlock();
    }
}

TASK_EXTERN
void task_attach(int64_t id)
{
    task_lock();
    struct task *co = task_map_delete(&task_detached, &(struct task){.id = id});
    if (co) {
        task_ndetached--;
    }
    task_unlock();
    if (co) {
        task_map_insert(&task_paused, co);
        task_npaused++;
    }
}

TASK_EXTERN
void *task_udata(void)
{
    return task_cur ? task_cur->udata : NULL;
}

TASK_EXTERN
size_t task_info_scheduled(void)
{
    return task_nyielders;
}

TASK_EXTERN
size_t task_info_paused(void)
{
    return task_npaused;
}

TASK_EXTERN
size_t task_info_running(void)
{
    size_t running = task_nrunners;
    if (task_cur) {
        /* Count the current coroutine */
        running++;
    }
    return running;
}

TASK_EXTERN
size_t task_info_detached(void)
{
    task_lock();
    size_t ndetached = task_ndetached;
    task_unlock();
    return ndetached;
}

/* Returns true if there are any coroutines running, yielding, or paused. */
TASK_EXTERN
bool task_active(void)
{
    /* Notice that detached coroutinues are not included. */
    return (task_nyielders + task_npaused + task_nrunners + !!task_cur) > 0;
}
