/*
 * ac_hashmap_test.c — Unit tests for ac_hashmap
 *
 * Tests: insert/get/remove, collision handling, resize at 75% load,
 * iterate all entries, empty map operations, binary keys with
 * embedded NULs, iterator remove during iteration, SipHash
 * determinism.
 */

#include "ac_hashmap.h"
#include "ac_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Test framework                                                     */
/* ------------------------------------------------------------------ */

static int g_tests_run   = 0;
static int g_tests_passed = 0;

#define TEST(name) static void name(void)
#define RUN(name) do { \
    g_tests_run++; \
    printf("  %-55s ", #name); \
    name(); \
    g_tests_passed++; \
    printf("PASS\n"); \
} while (0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAIL\n    %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

/* ------------------------------------------------------------------ */
/*  Tests                                                              */
/* ------------------------------------------------------------------ */

TEST(test_init_destroy)
{
    ac_hashmap_t hm;
    ASSERT(ac_hashmap_init(&hm, 0, 0) == AC_OK);
    ASSERT(hm.capacity >= 8);
    ASSERT(ac_hashmap_count(&hm) == 0);
    ac_hashmap_destroy(&hm);
}

TEST(test_init_custom_capacity)
{
    ac_hashmap_t hm;
    ASSERT(ac_hashmap_init(&hm, 128, 0) == AC_OK);
    ASSERT(hm.capacity == 128);
    ac_hashmap_destroy(&hm);
}

TEST(test_init_max_capacity)
{
    ac_hashmap_t hm;
    ASSERT(ac_hashmap_init(&hm, 1024, 512) == AC_OK);
    ASSERT(hm.capacity == 512);  /* capped to max */
    ASSERT(hm.max_capacity == 512);
    ac_hashmap_destroy(&hm);
}

TEST(test_init_null)
{
    ASSERT(ac_hashmap_init(NULL, 0, 0) == AC_ERR_INVAL);
}

TEST(test_put_get_single)
{
    ac_hashmap_t hm;
    int val = 42;
    void *got;

    ac_hashmap_init(&hm, 0, 0);
    ASSERT(ac_hashmap_put(&hm, "hello", 5, &val, NULL) == AC_OK);
    ASSERT(ac_hashmap_count(&hm) == 1);

    got = ac_hashmap_get(&hm, "hello", 5);
    ASSERT(got == &val);
    ASSERT(*(int *)got == 42);

    ac_hashmap_destroy(&hm);
}

TEST(test_put_update)
{
    ac_hashmap_t hm;
    int v1 = 1, v2 = 2;
    void *old = NULL;

    ac_hashmap_init(&hm, 0, 0);
    ac_hashmap_put(&hm, "key", 3, &v1, NULL);
    ASSERT(ac_hashmap_count(&hm) == 1);

    ASSERT(ac_hashmap_put(&hm, "key", 3, &v2, &old) == AC_OK);
    ASSERT(old == &v1);
    ASSERT(ac_hashmap_count(&hm) == 1);

    ASSERT(ac_hashmap_get(&hm, "key", 3) == &v2);
    ac_hashmap_destroy(&hm);
}

TEST(test_get_nonexistent)
{
    ac_hashmap_t hm;
    ac_hashmap_init(&hm, 0, 0);
    ASSERT(ac_hashmap_get(&hm, "nope", 4) == NULL);
    ac_hashmap_destroy(&hm);
}

TEST(test_get_null_map)
{
    ASSERT(ac_hashmap_get(NULL, "k", 1) == NULL);
}

TEST(test_remove_single)
{
    ac_hashmap_t hm;
    int val = 99;
    void *removed;

    ac_hashmap_init(&hm, 0, 0);
    ac_hashmap_put(&hm, "rm", 2, &val, NULL);
    ASSERT(ac_hashmap_count(&hm) == 1);

    removed = ac_hashmap_remove(&hm, "rm", 2);
    ASSERT(removed == &val);
    ASSERT(ac_hashmap_count(&hm) == 0);
    ASSERT(ac_hashmap_get(&hm, "rm", 2) == NULL);

    ac_hashmap_destroy(&hm);
}

TEST(test_remove_nonexistent)
{
    ac_hashmap_t hm;
    ac_hashmap_init(&hm, 0, 0);
    ASSERT(ac_hashmap_remove(&hm, "nope", 4) == NULL);
    ac_hashmap_destroy(&hm);
}

TEST(test_put_remove_reinsert)
{
    ac_hashmap_t hm;
    int v1 = 1, v2 = 2;

    ac_hashmap_init(&hm, 0, 0);
    ac_hashmap_put(&hm, "key", 3, &v1, NULL);
    ac_hashmap_remove(&hm, "key", 3);
    ASSERT(ac_hashmap_get(&hm, "key", 3) == NULL);

    ac_hashmap_put(&hm, "key", 3, &v2, NULL);
    ASSERT(ac_hashmap_get(&hm, "key", 3) == &v2);
    ASSERT(ac_hashmap_count(&hm) == 1);

    ac_hashmap_destroy(&hm);
}

TEST(test_many_entries)
{
    ac_hashmap_t hm;
    char keys[200][16];
    int vals[200];
    uint32_t i;

    ac_hashmap_init(&hm, 8, 0);  /* small initial, force multiple resizes */

    for (i = 0; i < 200; i++) {
        snprintf(keys[i], sizeof(keys[i]), "key_%03u", i);
        vals[i] = (int)i;
        ASSERT(ac_hashmap_put(&hm, keys[i], (uint32_t)strlen(keys[i]),
                              &vals[i], NULL) == AC_OK);
    }

    ASSERT(ac_hashmap_count(&hm) == 200);

    /* Verify all can be retrieved */
    for (i = 0; i < 200; i++) {
        int *got = (int *)ac_hashmap_get(&hm, keys[i],
                                         (uint32_t)strlen(keys[i]));
        ASSERT(got != NULL);
        ASSERT(*got == (int)i);
    }

    ac_hashmap_destroy(&hm);
}

TEST(test_binary_key_with_nuls)
{
    ac_hashmap_t hm;
    uint8_t key1[] = {0x00, 0x01, 0x00, 0x02};
    uint8_t key2[] = {0x00, 0x01, 0x00, 0x03};
    int v1 = 10, v2 = 20;

    ac_hashmap_init(&hm, 0, 0);
    ASSERT(ac_hashmap_put(&hm, key1, 4, &v1, NULL) == AC_OK);
    ASSERT(ac_hashmap_put(&hm, key2, 4, &v2, NULL) == AC_OK);
    ASSERT(ac_hashmap_count(&hm) == 2);

    ASSERT(ac_hashmap_get(&hm, key1, 4) == &v1);
    ASSERT(ac_hashmap_get(&hm, key2, 4) == &v2);

    ac_hashmap_destroy(&hm);
}

TEST(test_binary_key_all_zeros)
{
    ac_hashmap_t hm;
    uint8_t key[32];
    int val = 77;

    memset(key, 0, sizeof(key));
    ac_hashmap_init(&hm, 0, 0);
    ASSERT(ac_hashmap_put(&hm, key, 32, &val, NULL) == AC_OK);
    ASSERT(ac_hashmap_get(&hm, key, 32) == &val);
    ac_hashmap_destroy(&hm);
}

TEST(test_iterate_all)
{
    ac_hashmap_t hm;
    ac_hashmap_iter_t it;
    int vals[5] = {0, 1, 2, 3, 4};
    char keys[5][8] = {"aa", "bb", "cc", "dd", "ee"};
    int found[5] = {0};
    const void *k;
    uint32_t kl;
    void *v;
    uint32_t i, count = 0;

    ac_hashmap_init(&hm, 0, 0);
    for (i = 0; i < 5; i++)
        ac_hashmap_put(&hm, keys[i], (uint32_t)strlen(keys[i]),
                       &vals[i], NULL);

    ac_hashmap_iter_init(&it, &hm);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v)) {
        count++;
        for (i = 0; i < 5; i++) {
            if (kl == (uint32_t)strlen(keys[i]) &&
                memcmp(k, keys[i], kl) == 0) {
                ASSERT(v == &vals[i]);
                found[i] = 1;
            }
        }
    }
    ASSERT(count == 5);
    for (i = 0; i < 5; i++)
        ASSERT(found[i] == 1);

    ac_hashmap_destroy(&hm);
}

TEST(test_iterate_empty)
{
    ac_hashmap_t hm;
    ac_hashmap_iter_t it;
    const void *k;
    uint32_t kl;
    void *v;

    ac_hashmap_init(&hm, 0, 0);
    ac_hashmap_iter_init(&it, &hm);
    ASSERT(ac_hashmap_iter_next(&it, &k, &kl, &v) == 0);
    ac_hashmap_destroy(&hm);
}

TEST(test_iter_remove_during_iteration)
{
    /* S13: safe deletion during iteration */
    ac_hashmap_t hm;
    ac_hashmap_iter_t it;
    int vals[10];
    char keys[10][8];
    uint32_t i, removed = 0, kept = 0;
    const void *k;
    uint32_t kl;
    void *v;

    ac_hashmap_init(&hm, 0, 0);
    for (i = 0; i < 10; i++) {
        snprintf(keys[i], sizeof(keys[i]), "k%u", i);
        vals[i] = (int)i;
        ac_hashmap_put(&hm, keys[i], (uint32_t)strlen(keys[i]),
                       &vals[i], NULL);
    }

    /* Remove even-numbered entries during iteration */
    ac_hashmap_iter_init(&it, &hm);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v)) {
        int *ip = (int *)v;
        if (*ip % 2 == 0) {
            ac_hashmap_iter_remove(&it);
            removed++;
        } else {
            kept++;
        }
    }
    ASSERT(removed == 5);
    ASSERT(kept == 5);
    ASSERT(ac_hashmap_count(&hm) == 5);

    /* Verify odd entries still present */
    for (i = 1; i < 10; i += 2) {
        ASSERT(ac_hashmap_get(&hm, keys[i],
                              (uint32_t)strlen(keys[i])) == &vals[i]);
    }
    /* Verify even entries gone */
    for (i = 0; i < 10; i += 2) {
        ASSERT(ac_hashmap_get(&hm, keys[i],
                              (uint32_t)strlen(keys[i])) == NULL);
    }

    ac_hashmap_destroy(&hm);
}

TEST(test_resize_trigger)
{
    /* Fill to >75% and verify resize happens */
    ac_hashmap_t hm;
    int vals[100];
    char keys[100][8];
    uint32_t i, initial_cap;

    ac_hashmap_init(&hm, 8, 0);
    initial_cap = hm.capacity;
    ASSERT(initial_cap == 8);

    for (i = 0; i < 7; i++) {  /* 7/8 = 87.5% > 75% → triggers resize */
        snprintf(keys[i], sizeof(keys[i]), "r%u", i);
        vals[i] = (int)i;
        ac_hashmap_put(&hm, keys[i], (uint32_t)strlen(keys[i]),
                       &vals[i], NULL);
    }

    ASSERT(hm.capacity > initial_cap);
    ASSERT(ac_hashmap_count(&hm) == 7);

    /* All entries still accessible after resize */
    for (i = 0; i < 7; i++) {
        ASSERT(ac_hashmap_get(&hm, keys[i],
                              (uint32_t)strlen(keys[i])) == &vals[i]);
    }

    ac_hashmap_destroy(&hm);
}

TEST(test_max_capacity_enforced)
{
    ac_hashmap_t hm;
    int vals[100];
    char keys[100][8];
    uint32_t i;
    int last_rc = AC_OK;

    ac_hashmap_init(&hm, 8, 16);  /* max 16 slots */

    /* Should succeed up to ~12 entries (75% of 16) then fail */
    for (i = 0; i < 50; i++) {
        snprintf(keys[i], sizeof(keys[i]), "m%u", i);
        vals[i] = (int)i;
        last_rc = ac_hashmap_put(&hm, keys[i], (uint32_t)strlen(keys[i]),
                                 &vals[i], NULL);
        if (last_rc != AC_OK)
            break;
    }

    /* Should have hit the cap before 50 */
    ASSERT(i < 50);
    ASSERT(last_rc == AC_ERR_FULL || last_rc == AC_ERR_NOMEM);
    ASSERT(hm.capacity <= 16);

    ac_hashmap_destroy(&hm);
}

TEST(test_collision_handling)
{
    /*
     * Insert many entries with the same key prefix to stress
     * collision resolution. With 200 entries in a small initial map,
     * collisions are guaranteed.
     */
    ac_hashmap_t hm;
    int vals[200];
    uint32_t i;

    ac_hashmap_init(&hm, 8, 0);

    for (i = 0; i < 200; i++) {
        uint32_t key = i;
        vals[i] = (int)(i * 7);
        ASSERT(ac_hashmap_put(&hm, &key, sizeof(key),
                              &vals[i], NULL) == AC_OK);
    }

    ASSERT(ac_hashmap_count(&hm) == 200);

    for (i = 0; i < 200; i++) {
        uint32_t key = i;
        int *got = (int *)ac_hashmap_get(&hm, &key, sizeof(key));
        ASSERT(got != NULL);
        ASSERT(*got == (int)(i * 7));
    }

    ac_hashmap_destroy(&hm);
}

TEST(test_siphash_deterministic)
{
    uint8_t key[16];
    uint64_t h1, h2;
    uint8_t data[] = {0x01, 0x02, 0x03};

    memset(key, 0, 16);
    h1 = ac_siphash(key, data, 3);
    h2 = ac_siphash(key, data, 3);
    ASSERT(h1 == h2);

    /* Different key → different hash */
    key[0] = 1;
    h2 = ac_siphash(key, data, 3);
    ASSERT(h1 != h2);
}

TEST(test_siphash_empty)
{
    uint8_t key[16] = {0};
    uint64_t h = ac_siphash(key, "", 0);
    /* Just verify it doesn't crash and returns something */
    (void)h;
}

TEST(test_put_invalid_args)
{
    ac_hashmap_t hm;
    int val = 1;
    ac_hashmap_init(&hm, 0, 0);

    ASSERT(ac_hashmap_put(NULL, "k", 1, &val, NULL) == AC_ERR_INVAL);
    ASSERT(ac_hashmap_put(&hm, NULL, 1, &val, NULL) == AC_ERR_INVAL);
    ASSERT(ac_hashmap_put(&hm, "k", 0, &val, NULL) == AC_ERR_INVAL);

    ac_hashmap_destroy(&hm);
}

TEST(test_remove_after_many_tombstones)
{
    /* Ensure tombstones are cleaned up on resize */
    ac_hashmap_t hm;
    int vals[200];
    char keys[200][8];
    uint32_t i;

    ac_hashmap_init(&hm, 8, 0);

    /* Insert 6 entries (in cap=8, that's 75% → triggers resize to 16) */
    for (i = 0; i < 6; i++) {
        snprintf(keys[i], sizeof(keys[i]), "t%u", i);
        vals[i] = (int)i;
        ac_hashmap_put(&hm, keys[i], (uint32_t)strlen(keys[i]),
                       &vals[i], NULL);
    }
    /* Now cap is 16 after resize */

    /* Remove 5 of 6 → 5 tombstones, 1 live */
    for (i = 0; i < 5; i++) {
        ac_hashmap_remove(&hm, keys[i], (uint32_t)strlen(keys[i]));
    }
    ASSERT(ac_hashmap_count(&hm) == 1);
    ASSERT(hm.tomb_count == 5);

    /* Insert enough to trigger resize again: need (count+tomb) >= cap*75%
     * Currently count=1, tomb=5, cap=16. Need count+tomb >= 12.
     * So insert 6 more: count=7, tomb=5, total=12 >= 12. */
    for (i = 10; i < 16; i++) {
        snprintf(keys[i], sizeof(keys[i]), "t%u", i);
        vals[i] = (int)i;
        ac_hashmap_put(&hm, keys[i], (uint32_t)strlen(keys[i]),
                       &vals[i], NULL);
    }

    /* After resize, tombstones are cleaned */
    ASSERT(hm.tomb_count == 0);
    ASSERT(ac_hashmap_count(&hm) == 7);

    /* Verify all live entries accessible */
    ASSERT(ac_hashmap_get(&hm, keys[5], (uint32_t)strlen(keys[5])) == &vals[5]);
    for (i = 10; i < 16; i++) {
        ASSERT(ac_hashmap_get(&hm, keys[i],
                              (uint32_t)strlen(keys[i])) == &vals[i]);
    }

    ac_hashmap_destroy(&hm);
}

TEST(test_destroy_null)
{
    ac_hashmap_destroy(NULL);  /* must not crash */
}

TEST(test_count_null)
{
    ASSERT(ac_hashmap_count(NULL) == 0);
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("ac_hashmap tests:\n");

    RUN(test_init_destroy);
    RUN(test_init_custom_capacity);
    RUN(test_init_max_capacity);
    RUN(test_init_null);
    RUN(test_put_get_single);
    RUN(test_put_update);
    RUN(test_get_nonexistent);
    RUN(test_get_null_map);
    RUN(test_remove_single);
    RUN(test_remove_nonexistent);
    RUN(test_put_remove_reinsert);
    RUN(test_many_entries);
    RUN(test_binary_key_with_nuls);
    RUN(test_binary_key_all_zeros);
    RUN(test_iterate_all);
    RUN(test_iterate_empty);
    RUN(test_iter_remove_during_iteration);
    RUN(test_resize_trigger);
    RUN(test_max_capacity_enforced);
    RUN(test_collision_handling);
    RUN(test_siphash_deterministic);
    RUN(test_siphash_empty);
    RUN(test_put_invalid_args);
    RUN(test_remove_after_many_tombstones);
    RUN(test_destroy_null);
    RUN(test_count_null);

    printf("\n  %d/%d tests passed\n", g_tests_passed, g_tests_run);
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
