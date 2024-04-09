#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TASK_MINSTACKSIZE 131072 /* Recommended minimum stack size */

struct task_desc {
    void *stack;
    size_t stack_size;
    void (*entry)(void *udata);
    void (*cleanup)(void *stack, size_t stack_size, void *udata);
    void *udata;
};

/* Starts a new coroutine with the provided description. */
void task_start(struct task_desc *desc);

/* Causes the calling coroutine to relinquish the CPU.
 * This operation should be called from a coroutine, otherwise it does nothing.
 */
void task_yield(void);

/* Gets the identifier for the current coroutine.
 * This operation should be called from a coroutine, otherwise it returns zero.
 */
int64_t task_id(void);

/* Pause the current coroutine.
 * This operation should be called from a coroutine, otherwise it does nothing.
 */
void task_pause(void);

/* Resumes a paused coroutine.
 * If the id is invalid or does not belong to a paused coroutine then this
 * operation does nothing.
 * Calling task_resume(0) is a special case that continues a runloop.
 */
void task_resume(int64_t id);

/* Returns true if there are any coroutines running, yielding, or paused. */
bool task_active(void);

/* Detaches a coroutine from a thread.
 * This allows for moving coroutines between threads.
 * The coroutine must be currently paused before it can be detached, thus this
 * operation cannot be called from the coroutine belonging to the provided id.
 * If the id is invalid or does not belong to a paused coroutine then this
 * operation does nothing.
 */
void task_detach(int64_t id);

/* Attaches a coroutine to a thread.
 * This allows for moving coroutines between threads.
 * If the id is invalid or does not belong to a detached coroutine then this
 * operation does nothing.
 * Once attached, the coroutine will be paused.
 */
void task_attach(int64_t id);

/* Exits a coroutine early.
 * This _will not_ exit the program. Rather, it's for ending the current
 * coroutine and quickly switching to the thread's runloop before any other
 * scheduled (yielded) coroutines run.
 * This operation should be called from a coroutine, otherwise it does nothing.
 */
void task_exit(void);

/* Returns the user data of the currently running coroutine. */
void *task_udata(void);

/* General information and statistics */
size_t task_info_scheduled(void);
size_t task_info_running(void);
size_t task_info_paused(void);
size_t task_info_detached(void);
