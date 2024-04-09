#include <pthread.h>

#include "tests.h"

#define NCHILDREN 100

static __thread int nudid = 0;

void co_child_entry(void *udata)
{
    int udid = *(int *) udata;
    assert(udid == nudid);
}

void co_root_entry(void *udata)
{
    assert(*(int *) udata == 99999999);
    assert(*(int *) task_udata() == 99999999);
    assert(task_info_running() == 1);
    for (int i = 0; i < NCHILDREN; i++) {
        assert(started == 1 + i);
        assert(cleaned == 1 + i - 1);
        nudid = i;
        quick_start(co_child_entry, co_cleanup, &(int){i});
    }
}

void test_task_start(void)
{
    reset_stats();
    nudid = 0;
    assert(task_id() == 0);
    quick_start(co_root_entry, co_cleanup, &(int){99999999});
    assert(!task_active());
    assert(task_info_detached() == 0);
    assert(task_info_paused() == 0);
    assert(task_info_running() == 0);
    assert(task_info_scheduled() == 0);
    assert(started == NCHILDREN + 1);
    assert(cleaned == NCHILDREN + 1);
}

void co_sleep(void *udata)
{
    assert(*(int *) udata == 99999999);
    task_sleep(1e8); /* 100ms CPU-based sleep */
}

void test_task_sleep(void)
{
    reset_stats();
    quick_start(co_sleep, co_cleanup, &(int){99999999});
}

int64_t paused[NCHILDREN] = {0};
bool is_paused[NCHILDREN] = {0};
int npaused = 0;
bool all_resumed = false;

void co_pause_one(void *udata)
{
    int index = *(int *) udata;
    assert(index == npaused);
    paused[index] = task_id();

    /* pause in order */
    npaused++;
    is_paused[index] = true;
    task_pause();
    is_paused[index] = false;
    npaused--;
    while (!all_resumed)
        task_yield();

    /* pause in reverse */
    task_sleep(1e6 * (NCHILDREN - index));
    npaused++;
    is_paused[index] = true;
    task_pause();
    is_paused[index] = false;
    npaused--;
    while (!all_resumed) {
        task_yield();
    }

    /* pause in order, again */
    npaused++;
    is_paused[index] = true;
    task_pause();
    is_paused[index] = false;
    npaused--;
    while (!all_resumed) {
        task_yield();
    }

    /* pause in reverse, again */
    task_sleep(1e6 * (NCHILDREN - index));
    npaused++;
    is_paused[index] = true;
    task_pause();
    is_paused[index] = false;
    npaused--;
    while (!all_resumed) {
        task_yield();
    }
}

void co_resume_all(void *udata)
{
    (void) udata;

    /* wait for all to be paused */
    while (npaused < NCHILDREN) {
        task_yield();
    }
    all_resumed = false;
    /* resume in order */
    for (int i = 0; i < NCHILDREN; i++) {
        task_resume(paused[i]);
    }
    while (npaused > 0) {
        task_yield();
    }
    all_resumed = true;

    /* wait for all to be paused, again */
    while (npaused < NCHILDREN)
        task_yield();

    all_resumed = false;
    /* resume in order */
    for (int i = 0; i < NCHILDREN; i++) {
        task_resume(paused[i]);
    }
    while (npaused > 0) {
        task_yield();
    }
    all_resumed = true;

    /* wait for all to be paused, again */
    while (npaused < NCHILDREN) {
        task_yield();
    }
    all_resumed = false;
    /* resume in reverse order */
    for (int i = NCHILDREN - 1; i >= 0; i--) {
        task_resume(paused[i]);
    }
    while (npaused > 0) {
        task_yield();
    }
    all_resumed = true;

    /* wait for all to be paused, again */
    while (npaused < NCHILDREN) {
        task_yield();
    }
    all_resumed = false;
    /* resume in reverse order */
    for (int i = NCHILDREN - 1; i >= 0; i--) {
        task_resume(paused[i]);
    }
    while (npaused > 0) {
        task_yield();
    }
    all_resumed = true;
}

void test_task_pause(void)
{
    reset_stats();
    for (int i = 0; i < NCHILDREN; i++) {
        quick_start(co_pause_one, co_cleanup, &i);
    }
    quick_start(co_resume_all, co_cleanup, 0);
    while (task_active()) {
        task_resume(0);
    }
    assert(npaused == 0);
}

static int64_t thpaused[NCHILDREN] = {0};

void co_thread_one(void *udata)
{
    int index = *(int *) udata;
    int64_t id = task_id();
    thpaused[index] = id;
    task_sleep(1e6);
    task_pause();
}


void *thread0(void *arg)
{
    (void) arg;
    reset_stats();
    for (int i = 0; i < NCHILDREN; i++) {
        quick_start(co_thread_one, co_cleanup, &i);
    }
    while (task_active()) {
        if (task_info_paused() == NCHILDREN) {
            /* Detach all paused */
            for (int i = 0; i < NCHILDREN; i++) {
                task_detach(thpaused[i]);
            }
        }
        task_resume(0);
    }
    return NULL;
}

void *thread1(void *arg)
{
    (void) arg;
    reset_stats();
    while (task_info_detached() < NCHILDREN) {
        /* Wait */
    }

    /* Attach all paused */
    for (int i = 0; i < NCHILDREN; i++) {
        task_attach(thpaused[i]);
        task_resume(thpaused[i]);
    }
    while (task_active()) {
        task_resume(0);
    }
    return NULL;
}

void test_task_detach(void)
{
    pthread_t th0, th1;
    assert(pthread_create(&th0, 0, thread0, 0) == 0);
    assert(pthread_create(&th1, 0, thread1, 0) == 0);
    assert(pthread_join(th0, 0) == 0);
    assert(pthread_join(th1, 0) == 0);
}

int exitvals[6] = {0};
int nexitvals = 0;

void co_two(void *udata)
{
    (void) udata;
    task_sleep(1e7 * 2);
    exitvals[nexitvals++] = 2;
}

void co_three(void *udata)
{
    (void) udata;
    task_sleep(1e7);
    exitvals[nexitvals++] = 3;
}

void co_four(void *udata)
{
    (void) udata;
    exitvals[nexitvals++] = 4;
    task_yield();
}


void co_one(void *udata)
{
    (void) udata;
    exitvals[nexitvals++] = 1;
    quick_start(co_two, co_cleanup, 0);
    quick_start(co_three, co_cleanup, 0);
    quick_start(co_four, co_cleanup, 0);
    task_exit();
}

void test_task_exit(void)
{
    memset(exitvals, 0, sizeof(exitvals));
    nexitvals = 0;
    quick_start(co_one, co_cleanup, 0);
    exitvals[nexitvals++] = -1;
    while (task_active()) {
        task_resume(0);
    }
    exitvals[nexitvals++] = -2;
    assert(nexitvals == 6);
    assert(exitvals[0] == 1);
    assert(exitvals[1] == 4);
    assert(exitvals[2] == -1);
    assert(exitvals[3] == 3);
    assert(exitvals[4] == 2);
    assert(exitvals[5] == -2);
}

struct order_ctx {
    char a[10];
    int i;
};

void co_yield1(void *udata)
{
    assert(udata);
    char *a = ((struct order_ctx *) udata)->a;
    int *i = &((struct order_ctx *) udata)->i;
    a[(*i)++] = 'B';
    task_yield();
    a[(*i)++] = 'D';
}

void co_yield2(void *udata)
{
    assert(udata);
    char *a = ((struct order_ctx *) udata)->a;
    int *i = &((struct order_ctx *) udata)->i;
    a[(*i)++] = 'E';
    task_yield();
    a[(*i)++] = 'G';
}

void co_yield(void *udata)
{
    assert(udata);
    char *a = ((struct order_ctx *) udata)->a;
    int *i = &((struct order_ctx *) udata)->i;
    a[(*i)++] = 'A';
    quick_start(co_yield1, co_cleanup, udata);
    a[(*i)++] = 'C';
    quick_start(co_yield2, co_cleanup, udata);
    a[(*i)++] = 'F';
    task_yield();
    a[(*i)++] = 'H';
}


void test_task_order(void)
{
    /* Tests the scheduling order. */
    struct order_ctx ctx = {0};
    char *a = ctx.a;
    int *i = &ctx.i;
    quick_start(co_yield, co_cleanup, &ctx);
    a[(*i)++] = '\0';
    char exp[] = "ABCDEFGH";
    if (strcmp(a, exp) != 0) {
        printf("expected '%s' got '%s'\n", exp, a);
        abort();
    }
}

int main(int argc, char **argv)
{
    do_test(test_task_start);
    do_test(test_task_sleep);
    do_test(test_task_pause);
    do_test(test_task_exit);
    do_test(test_task_order);
    do_test(test_task_detach);
    return 0;
}
