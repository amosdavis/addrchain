/*
 * ac_dag_test.c — Unit tests for ac_dag.c
 *
 * Tests: init/destroy, add_node, remove_node, add_edge,
 *        cycle detection, has_dependents, remove_node with
 *        dependents fails, remove_node removes parent edges.
 *
 * Mitigates: S05, S19, S21, K06
 */

#include "ac_dag.h"
#include "ac_crypto.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Test framework                                                     */
/* ------------------------------------------------------------------ */

static int test_count  = 0;
static int pass_count  = 0;
static int fail_count  = 0;

#define TEST(name) do { \
    test_count++; \
    printf("  [%02d] %-55s ", test_count, name); \
} while (0)

#define PASS() do { pass_count++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { fail_count++; printf("FAIL: %s\n", msg); } while (0)

#define ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { FAIL(msg); return; } \
} while (0)

#define ASSERT_NE(a, b, msg) do { \
    if ((a) == (b)) { FAIL(msg); return; } \
} while (0)

#define ASSERT_OK(rc, msg) ASSERT_EQ(rc, AC_OK, msg)

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

static void make_id(uint8_t id[AC_MAX_ADDR_LEN], uint8_t seed)
{
    memset(id, seed, AC_MAX_ADDR_LEN);
}

/* ------------------------------------------------------------------ */
/*  Tests                                                              */
/* ------------------------------------------------------------------ */

static void test_init_destroy(void)
{
    ac_dag_t dag;

    TEST("init and destroy");

    ASSERT_OK(ac_dag_init(&dag), "init failed");
    ASSERT_EQ(ac_dag_node_count(&dag), 0, "node_count != 0");
    ASSERT_EQ(ac_dag_edge_count(&dag), 0, "edge_count != 0");
    ac_dag_destroy(&dag);

    PASS();
}

static void test_add_node(void)
{
    ac_dag_t dag;
    uint8_t id1[AC_MAX_ADDR_LEN];
    uint8_t id2[AC_MAX_ADDR_LEN];

    TEST("add_node basic");

    ASSERT_OK(ac_dag_init(&dag), "init failed");

    make_id(id1, 0x01);
    make_id(id2, 0x02);

    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id1), "add node1");
    ASSERT_EQ(ac_dag_node_count(&dag), 1, "count != 1");

    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_CLAIM, id2), "add node2");
    ASSERT_EQ(ac_dag_node_count(&dag), 2, "count != 2");

    ac_dag_destroy(&dag);
    PASS();
}

static void test_add_node_duplicate(void)
{
    ac_dag_t dag;
    uint8_t id1[AC_MAX_ADDR_LEN];

    TEST("add_node duplicate returns AC_ERR_EXIST");

    ASSERT_OK(ac_dag_init(&dag), "init failed");

    make_id(id1, 0x01);
    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id1), "add node1");
    ASSERT_EQ(ac_dag_add_node(&dag, AC_RES_SUBNET, id1), AC_ERR_EXIST,
              "duplicate should fail");
    ASSERT_EQ(ac_dag_node_count(&dag), 1, "count != 1");

    ac_dag_destroy(&dag);
    PASS();
}

static void test_same_id_different_type(void)
{
    ac_dag_t dag;
    uint8_t id1[AC_MAX_ADDR_LEN];

    TEST("same id, different type are distinct nodes");

    ASSERT_OK(ac_dag_init(&dag), "init failed");

    make_id(id1, 0x01);
    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id1), "add subnet");
    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_CLAIM, id1), "add claim");
    ASSERT_EQ(ac_dag_node_count(&dag), 2, "count != 2");

    ac_dag_destroy(&dag);
    PASS();
}

static void test_remove_node(void)
{
    ac_dag_t dag;
    uint8_t id1[AC_MAX_ADDR_LEN];

    TEST("remove_node basic");

    ASSERT_OK(ac_dag_init(&dag), "init failed");

    make_id(id1, 0x01);
    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id1), "add node");
    ASSERT_EQ(ac_dag_node_count(&dag), 1, "count != 1");

    ASSERT_OK(ac_dag_remove_node(&dag, AC_RES_SUBNET, id1), "remove node");
    ASSERT_EQ(ac_dag_node_count(&dag), 0, "count != 0");

    ac_dag_destroy(&dag);
    PASS();
}

static void test_remove_nonexistent(void)
{
    ac_dag_t dag;
    uint8_t id1[AC_MAX_ADDR_LEN];

    TEST("remove_node nonexistent returns AC_ERR_NOENT");

    ASSERT_OK(ac_dag_init(&dag), "init failed");

    make_id(id1, 0xFF);
    ASSERT_EQ(ac_dag_remove_node(&dag, AC_RES_SUBNET, id1), AC_ERR_NOENT,
              "remove nonexistent should fail");

    ac_dag_destroy(&dag);
    PASS();
}

static void test_add_edge(void)
{
    ac_dag_t dag;
    uint8_t id_parent[AC_MAX_ADDR_LEN];
    uint8_t id_child[AC_MAX_ADDR_LEN];

    TEST("add_edge basic");

    ASSERT_OK(ac_dag_init(&dag), "init failed");

    make_id(id_parent, 0x01);
    make_id(id_child, 0x02);

    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_parent), "add parent");
    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_CLAIM, id_child), "add child");

    ASSERT_OK(ac_dag_add_edge(&dag,
                              AC_RES_SUBNET, id_parent,
                              AC_RES_CLAIM, id_child), "add edge");
    ASSERT_EQ(ac_dag_edge_count(&dag), 1, "edge_count != 1");

    ac_dag_destroy(&dag);
    PASS();
}

static void test_add_edge_nonexistent_parent(void)
{
    ac_dag_t dag;
    uint8_t id_parent[AC_MAX_ADDR_LEN];
    uint8_t id_child[AC_MAX_ADDR_LEN];

    TEST("add_edge with nonexistent parent fails");

    ASSERT_OK(ac_dag_init(&dag), "init failed");

    make_id(id_parent, 0x01);
    make_id(id_child, 0x02);

    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_CLAIM, id_child), "add child");

    ASSERT_EQ(ac_dag_add_edge(&dag,
                              AC_RES_SUBNET, id_parent,
                              AC_RES_CLAIM, id_child), AC_ERR_NOENT,
              "should fail with NOENT");

    ac_dag_destroy(&dag);
    PASS();
}

static void test_add_edge_nonexistent_child(void)
{
    ac_dag_t dag;
    uint8_t id_parent[AC_MAX_ADDR_LEN];
    uint8_t id_child[AC_MAX_ADDR_LEN];

    TEST("add_edge with nonexistent child fails");

    ASSERT_OK(ac_dag_init(&dag), "init failed");

    make_id(id_parent, 0x01);
    make_id(id_child, 0x02);

    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_parent), "add parent");

    ASSERT_EQ(ac_dag_add_edge(&dag,
                              AC_RES_SUBNET, id_parent,
                              AC_RES_CLAIM, id_child), AC_ERR_NOENT,
              "should fail with NOENT");

    ac_dag_destroy(&dag);
    PASS();
}

static void test_cycle_detection_direct(void)
{
    ac_dag_t dag;
    uint8_t id_a[AC_MAX_ADDR_LEN];
    uint8_t id_b[AC_MAX_ADDR_LEN];

    TEST("cycle detection: direct cycle A->B->A");

    ASSERT_OK(ac_dag_init(&dag), "init failed");

    make_id(id_a, 0x01);
    make_id(id_b, 0x02);

    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_a), "add A");
    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_b), "add B");

    /* A -> B (B depends on A) */
    ASSERT_OK(ac_dag_add_edge(&dag,
                              AC_RES_SUBNET, id_a,
                              AC_RES_SUBNET, id_b), "edge A->B");

    /* B -> A would create cycle */
    ASSERT_EQ(ac_dag_add_edge(&dag,
                              AC_RES_SUBNET, id_b,
                              AC_RES_SUBNET, id_a), AC_ERR_INVAL,
              "cycle should be rejected");
    ASSERT_EQ(ac_dag_edge_count(&dag), 1, "edge_count != 1");

    ac_dag_destroy(&dag);
    PASS();
}

static void test_cycle_detection_indirect(void)
{
    ac_dag_t dag;
    uint8_t id_a[AC_MAX_ADDR_LEN];
    uint8_t id_b[AC_MAX_ADDR_LEN];
    uint8_t id_c[AC_MAX_ADDR_LEN];

    TEST("cycle detection: indirect cycle A->B->C->A");

    ASSERT_OK(ac_dag_init(&dag), "init failed");

    make_id(id_a, 0x01);
    make_id(id_b, 0x02);
    make_id(id_c, 0x03);

    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_a), "add A");
    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_b), "add B");
    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_c), "add C");

    ASSERT_OK(ac_dag_add_edge(&dag, AC_RES_SUBNET, id_a,
                              AC_RES_SUBNET, id_b), "edge A->B");
    ASSERT_OK(ac_dag_add_edge(&dag, AC_RES_SUBNET, id_b,
                              AC_RES_SUBNET, id_c), "edge B->C");

    /* C -> A would create cycle */
    ASSERT_EQ(ac_dag_add_edge(&dag, AC_RES_SUBNET, id_c,
                              AC_RES_SUBNET, id_a), AC_ERR_INVAL,
              "indirect cycle should be rejected");

    ac_dag_destroy(&dag);
    PASS();
}

static void test_cycle_detection_self_loop(void)
{
    ac_dag_t dag;
    uint8_t id_a[AC_MAX_ADDR_LEN];

    TEST("cycle detection: self-loop A->A");

    ASSERT_OK(ac_dag_init(&dag), "init failed");

    make_id(id_a, 0x01);
    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_a), "add A");

    ASSERT_EQ(ac_dag_add_edge(&dag, AC_RES_SUBNET, id_a,
                              AC_RES_SUBNET, id_a), AC_ERR_INVAL,
              "self-loop should be rejected");

    ac_dag_destroy(&dag);
    PASS();
}

static void test_would_cycle(void)
{
    ac_dag_t dag;
    uint8_t id_a[AC_MAX_ADDR_LEN];
    uint8_t id_b[AC_MAX_ADDR_LEN];

    TEST("would_cycle query");

    ASSERT_OK(ac_dag_init(&dag), "init failed");

    make_id(id_a, 0x01);
    make_id(id_b, 0x02);

    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_a), "add A");
    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_b), "add B");

    /* No edge yet — no cycle */
    ASSERT_EQ(ac_dag_would_cycle(&dag, AC_RES_SUBNET, id_a,
                                 AC_RES_SUBNET, id_b), 0,
              "no cycle expected");

    ASSERT_OK(ac_dag_add_edge(&dag, AC_RES_SUBNET, id_a,
                              AC_RES_SUBNET, id_b), "edge A->B");

    /* B->A would cycle */
    ASSERT_EQ(ac_dag_would_cycle(&dag, AC_RES_SUBNET, id_b,
                                 AC_RES_SUBNET, id_a), 1,
              "cycle expected");

    ac_dag_destroy(&dag);
    PASS();
}

static void test_has_dependents(void)
{
    ac_dag_t dag;
    uint8_t id_parent[AC_MAX_ADDR_LEN];
    uint8_t id_child[AC_MAX_ADDR_LEN];

    TEST("has_dependents");

    ASSERT_OK(ac_dag_init(&dag), "init failed");

    make_id(id_parent, 0x01);
    make_id(id_child, 0x02);

    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_parent), "add parent");
    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_CLAIM, id_child), "add child");

    ASSERT_EQ(ac_dag_has_dependents(&dag, AC_RES_SUBNET, id_parent), 0,
              "no dependents yet");

    ASSERT_OK(ac_dag_add_edge(&dag, AC_RES_SUBNET, id_parent,
                              AC_RES_CLAIM, id_child), "add edge");

    ASSERT_EQ(ac_dag_has_dependents(&dag, AC_RES_SUBNET, id_parent), 1,
              "should have dependents");
    ASSERT_EQ(ac_dag_dependent_count(&dag, AC_RES_SUBNET, id_parent), 1,
              "dependent_count != 1");

    /* Child has no dependents of its own */
    ASSERT_EQ(ac_dag_has_dependents(&dag, AC_RES_CLAIM, id_child), 0,
              "child should have no dependents");

    ac_dag_destroy(&dag);
    PASS();
}

static void test_remove_node_with_dependents_fails(void)
{
    ac_dag_t dag;
    uint8_t id_parent[AC_MAX_ADDR_LEN];
    uint8_t id_child[AC_MAX_ADDR_LEN];

    TEST("remove_node with dependents fails");

    ASSERT_OK(ac_dag_init(&dag), "init failed");

    make_id(id_parent, 0x01);
    make_id(id_child, 0x02);

    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_parent), "add parent");
    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_CLAIM, id_child), "add child");
    ASSERT_OK(ac_dag_add_edge(&dag, AC_RES_SUBNET, id_parent,
                              AC_RES_CLAIM, id_child), "add edge");

    /* Parent has dependents — removal must fail */
    ASSERT_EQ(ac_dag_remove_node(&dag, AC_RES_SUBNET, id_parent), AC_ERR_EXIST,
              "should fail with EXIST");
    ASSERT_EQ(ac_dag_node_count(&dag), 2, "count should still be 2");

    ac_dag_destroy(&dag);
    PASS();
}

static void test_remove_node_removes_parent_edges(void)
{
    ac_dag_t dag;
    uint8_t id_parent[AC_MAX_ADDR_LEN];
    uint8_t id_child[AC_MAX_ADDR_LEN];

    TEST("remove_node prunes parent edges (S19)");

    ASSERT_OK(ac_dag_init(&dag), "init failed");

    make_id(id_parent, 0x01);
    make_id(id_child, 0x02);

    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_parent), "add parent");
    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_CLAIM, id_child), "add child");
    ASSERT_OK(ac_dag_add_edge(&dag, AC_RES_SUBNET, id_parent,
                              AC_RES_CLAIM, id_child), "add edge");

    ASSERT_EQ(ac_dag_edge_count(&dag), 1, "edge_count != 1");
    ASSERT_EQ(ac_dag_has_dependents(&dag, AC_RES_SUBNET, id_parent), 1,
              "parent should have dependents");

    /* Remove child (no dependents of its own) — should prune parent edge */
    ASSERT_OK(ac_dag_remove_node(&dag, AC_RES_CLAIM, id_child), "remove child");
    ASSERT_EQ(ac_dag_node_count(&dag), 1, "count != 1");
    ASSERT_EQ(ac_dag_edge_count(&dag), 0, "edge_count != 0");
    ASSERT_EQ(ac_dag_has_dependents(&dag, AC_RES_SUBNET, id_parent), 0,
              "parent should have no dependents");

    ac_dag_destroy(&dag);
    PASS();
}

static void test_remove_edge(void)
{
    ac_dag_t dag;
    uint8_t id_a[AC_MAX_ADDR_LEN];
    uint8_t id_b[AC_MAX_ADDR_LEN];

    TEST("remove_edge basic");

    ASSERT_OK(ac_dag_init(&dag), "init failed");

    make_id(id_a, 0x01);
    make_id(id_b, 0x02);

    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_a), "add A");
    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_b), "add B");
    ASSERT_OK(ac_dag_add_edge(&dag, AC_RES_SUBNET, id_a,
                              AC_RES_SUBNET, id_b), "add edge");
    ASSERT_EQ(ac_dag_edge_count(&dag), 1, "edge_count != 1");

    ASSERT_OK(ac_dag_remove_edge(&dag, AC_RES_SUBNET, id_a,
                                 AC_RES_SUBNET, id_b), "remove edge");
    ASSERT_EQ(ac_dag_edge_count(&dag), 0, "edge_count != 0");

    ac_dag_destroy(&dag);
    PASS();
}

static void test_remove_edge_nonexistent(void)
{
    ac_dag_t dag;
    uint8_t id_a[AC_MAX_ADDR_LEN];
    uint8_t id_b[AC_MAX_ADDR_LEN];

    TEST("remove_edge nonexistent returns AC_ERR_NOENT");

    ASSERT_OK(ac_dag_init(&dag), "init failed");

    make_id(id_a, 0x01);
    make_id(id_b, 0x02);

    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_a), "add A");
    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_b), "add B");

    ASSERT_EQ(ac_dag_remove_edge(&dag, AC_RES_SUBNET, id_a,
                                 AC_RES_SUBNET, id_b), AC_ERR_NOENT,
              "should fail with NOENT");

    ac_dag_destroy(&dag);
    PASS();
}

static void test_diamond_no_cycle(void)
{
    ac_dag_t dag;
    uint8_t id_a[AC_MAX_ADDR_LEN];
    uint8_t id_b[AC_MAX_ADDR_LEN];
    uint8_t id_c[AC_MAX_ADDR_LEN];
    uint8_t id_d[AC_MAX_ADDR_LEN];

    TEST("diamond graph A->{B,C}->D is valid DAG");

    ASSERT_OK(ac_dag_init(&dag), "init failed");

    make_id(id_a, 0x01);
    make_id(id_b, 0x02);
    make_id(id_c, 0x03);
    make_id(id_d, 0x04);

    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_a), "add A");
    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_b), "add B");
    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_c), "add C");
    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_d), "add D");

    ASSERT_OK(ac_dag_add_edge(&dag, AC_RES_SUBNET, id_a,
                              AC_RES_SUBNET, id_b), "A->B");
    ASSERT_OK(ac_dag_add_edge(&dag, AC_RES_SUBNET, id_a,
                              AC_RES_SUBNET, id_c), "A->C");
    ASSERT_OK(ac_dag_add_edge(&dag, AC_RES_SUBNET, id_b,
                              AC_RES_SUBNET, id_d), "B->D");
    ASSERT_OK(ac_dag_add_edge(&dag, AC_RES_SUBNET, id_c,
                              AC_RES_SUBNET, id_d), "C->D");

    ASSERT_EQ(ac_dag_node_count(&dag), 4, "node_count != 4");
    ASSERT_EQ(ac_dag_edge_count(&dag), 4, "edge_count != 4");
    ASSERT_EQ(ac_dag_dependent_count(&dag, AC_RES_SUBNET, id_a), 2,
              "A should have 2 dependents");

    ac_dag_destroy(&dag);
    PASS();
}

static void test_multiple_parents_remove(void)
{
    ac_dag_t dag;
    uint8_t id_a[AC_MAX_ADDR_LEN];
    uint8_t id_b[AC_MAX_ADDR_LEN];
    uint8_t id_c[AC_MAX_ADDR_LEN];

    TEST("remove node with multiple parents prunes all edges");

    ASSERT_OK(ac_dag_init(&dag), "init failed");

    make_id(id_a, 0x01);
    make_id(id_b, 0x02);
    make_id(id_c, 0x03);

    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_a), "add A");
    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_SUBNET, id_b), "add B");
    ASSERT_OK(ac_dag_add_node(&dag, AC_RES_CLAIM, id_c), "add C");

    /* C depends on both A and B */
    ASSERT_OK(ac_dag_add_edge(&dag, AC_RES_SUBNET, id_a,
                              AC_RES_CLAIM, id_c), "A->C");
    ASSERT_OK(ac_dag_add_edge(&dag, AC_RES_SUBNET, id_b,
                              AC_RES_CLAIM, id_c), "B->C");

    ASSERT_EQ(ac_dag_edge_count(&dag), 2, "edge_count != 2");

    /* Remove C — should clean up edges from both A and B */
    ASSERT_OK(ac_dag_remove_node(&dag, AC_RES_CLAIM, id_c), "remove C");

    ASSERT_EQ(ac_dag_edge_count(&dag), 0, "edge_count != 0");
    ASSERT_EQ(ac_dag_has_dependents(&dag, AC_RES_SUBNET, id_a), 0,
              "A should have no dependents");
    ASSERT_EQ(ac_dag_has_dependents(&dag, AC_RES_SUBNET, id_b), 0,
              "B should have no dependents");

    ac_dag_destroy(&dag);
    PASS();
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("ac_dag tests:\n");

    test_init_destroy();
    test_add_node();
    test_add_node_duplicate();
    test_same_id_different_type();
    test_remove_node();
    test_remove_nonexistent();
    test_add_edge();
    test_add_edge_nonexistent_parent();
    test_add_edge_nonexistent_child();
    test_cycle_detection_direct();
    test_cycle_detection_indirect();
    test_cycle_detection_self_loop();
    test_would_cycle();
    test_has_dependents();
    test_remove_node_with_dependents_fails();
    test_remove_node_removes_parent_edges();
    test_remove_edge();
    test_remove_edge_nonexistent();
    test_diamond_no_cycle();
    test_multiple_parents_remove();

    printf("\nResults: %d/%d passed", pass_count, test_count);
    if (fail_count > 0)
        printf(", %d FAILED", fail_count);
    printf("\n");

    return fail_count > 0 ? 1 : 0;
}
