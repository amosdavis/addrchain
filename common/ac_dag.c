/*
 * ac_dag.c — Directed Acyclic Graph dependency tracking implementation
 *
 * Tracks resource dependencies as a DAG with cycle detection.
 * Uses iterative stack-based DFS for cycle detection (K06: no recursion).
 * Thread-safe: all public functions acquire dag->lock.
 *
 * Mitigates: S05 (cycle detection), S19 (prune on remove),
 *            S21 (topo cache invalidation), K06 (no recursion)
 */

#include "ac_dag.h"

#include <string.h>

/* ================================================================== */
/*  Internal helpers                                                   */
/* ================================================================== */

/* Build a 33-byte DAG key from type + id */
static void dag_make_key(uint8_t key[AC_DAG_KEY_LEN],
                         uint8_t type,
                         const uint8_t id[AC_MAX_ADDR_LEN])
{
    key[0] = type;
    memcpy(key + 1, id, AC_MAX_ADDR_LEN);
}

/* Look up a node by key (caller holds lock) */
static ac_dag_node_t *dag_find_node(ac_dag_t *dag, const uint8_t key[AC_DAG_KEY_LEN])
{
    return (ac_dag_node_t *)ac_hashmap_get(&dag->nodes, key, AC_DAG_KEY_LEN);
}

/* Free a single dag node: destroy its child/parent hashmaps and free it */
static void dag_free_node(ac_dag_node_t *node)
{
    ac_hashmap_destroy(&node->children);
    ac_hashmap_destroy(&node->parents);
    ac_free(node);
}

/* Dummy value for edge hashmaps — we only care about key presence */
#define DAG_EDGE_MARKER ((void *)(uintptr_t)1)

/* ================================================================== */
/*  DFS-based cycle detection (iterative, K06)                         */
/* ================================================================== */

/* DFS stack for cycle detection */
typedef struct {
    uint8_t *keys;      /* array of AC_DAG_KEY_LEN-sized entries */
    uint32_t count;
    uint32_t capacity;
} dag_stack_t;

static int dag_stack_init(dag_stack_t *s, uint32_t initial_cap)
{
    s->count = 0;
    s->capacity = initial_cap > 0 ? initial_cap : 16;
    s->keys = (uint8_t *)ac_alloc((size_t)s->capacity * AC_DAG_KEY_LEN,
                                  AC_MEM_NORMAL);
    return s->keys ? AC_OK : AC_ERR_NOMEM;
}

static void dag_stack_destroy(dag_stack_t *s)
{
    ac_free(s->keys);
    s->keys = NULL;
    s->count = 0;
    s->capacity = 0;
}

static int dag_stack_push(dag_stack_t *s, const uint8_t key[AC_DAG_KEY_LEN])
{
    if (s->count == s->capacity) {
        uint32_t new_cap = s->capacity * 2;
        uint8_t *new_keys = (uint8_t *)ac_alloc(
            (size_t)new_cap * AC_DAG_KEY_LEN, AC_MEM_NORMAL);
        if (!new_keys)
            return AC_ERR_NOMEM;
        memcpy(new_keys, s->keys, (size_t)s->count * AC_DAG_KEY_LEN);
        ac_free(s->keys);
        s->keys = new_keys;
        s->capacity = new_cap;
    }
    memcpy(s->keys + (size_t)s->count * AC_DAG_KEY_LEN, key, AC_DAG_KEY_LEN);
    s->count++;
    return AC_OK;
}

static int dag_stack_pop(dag_stack_t *s, uint8_t key[AC_DAG_KEY_LEN])
{
    if (s->count == 0)
        return 0;
    s->count--;
    memcpy(key, s->keys + (size_t)s->count * AC_DAG_KEY_LEN, AC_DAG_KEY_LEN);
    return 1;
}

/*
 * Iterative DFS from start_key following children edges.
 * Returns 1 if target_key is reachable from start_key, 0 otherwise.
 * Caller holds dag->lock.
 */
static int dag_dfs_reaches(ac_dag_t *dag,
                           const uint8_t start_key[AC_DAG_KEY_LEN],
                           const uint8_t target_key[AC_DAG_KEY_LEN])
{
    dag_stack_t stack;
    ac_hashmap_t visited;
    uint8_t cur[AC_DAG_KEY_LEN];
    int found = 0;

    if (memcmp(start_key, target_key, AC_DAG_KEY_LEN) == 0)
        return 1;

    if (dag_stack_init(&stack, 16) != AC_OK)
        return 0;

    if (ac_hashmap_init(&visited, 0, 0) != AC_OK) {
        dag_stack_destroy(&stack);
        return 0;
    }

    if (dag_stack_push(&stack, start_key) != AC_OK) {
        ac_hashmap_destroy(&visited);
        dag_stack_destroy(&stack);
        return 0;
    }

    while (dag_stack_pop(&stack, cur)) {
        ac_dag_node_t *node;
        ac_hashmap_iter_t it;
        const void *child_key;
        uint32_t child_key_len;
        void *child_val;

        if (ac_hashmap_get(&visited, cur, AC_DAG_KEY_LEN))
            continue;

        if (ac_hashmap_put(&visited, cur, AC_DAG_KEY_LEN,
                           DAG_EDGE_MARKER, NULL) != AC_OK)
            break;

        if (memcmp(cur, target_key, AC_DAG_KEY_LEN) == 0) {
            found = 1;
            break;
        }

        node = dag_find_node(dag, cur);
        if (!node)
            continue;

        ac_hashmap_iter_init(&it, &node->children);
        while (ac_hashmap_iter_next(&it, &child_key, &child_key_len,
                                    &child_val)) {
            if (!ac_hashmap_get(&visited, child_key, child_key_len)) {
                if (dag_stack_push(&stack,
                                   (const uint8_t *)child_key) != AC_OK)
                    break;
            }
        }
    }

    ac_hashmap_destroy(&visited);
    dag_stack_destroy(&stack);
    return found;
}

/* ================================================================== */
/*  Public API                                                         */
/* ================================================================== */

int ac_dag_init(ac_dag_t *dag)
{
    int rc;

    memset(dag, 0, sizeof(*dag));

    rc = ac_hashmap_init(&dag->nodes, 0, 0);
    if (rc != AC_OK)
        return rc;

    rc = ac_mutex_init(&dag->lock);
    if (rc != AC_OK) {
        ac_hashmap_destroy(&dag->nodes);
        return rc;
    }

    dag->node_count = 0;
    dag->edge_count = 0;
    dag->topo_valid = 0;
    return AC_OK;
}

void ac_dag_destroy(ac_dag_t *dag)
{
    ac_hashmap_iter_t it;
    const void *key;
    uint32_t key_len;
    void *val;

    ac_mutex_lock(&dag->lock);

    ac_hashmap_iter_init(&it, &dag->nodes);
    while (ac_hashmap_iter_next(&it, &key, &key_len, &val)) {
        dag_free_node((ac_dag_node_t *)val);
    }
    ac_hashmap_destroy(&dag->nodes);

    dag->node_count = 0;
    dag->edge_count = 0;
    dag->topo_valid = 0;

    ac_mutex_unlock(&dag->lock);
    ac_mutex_destroy(&dag->lock);
}

int ac_dag_add_node(ac_dag_t *dag, uint8_t type,
                    const uint8_t id[AC_MAX_ADDR_LEN])
{
    uint8_t key[AC_DAG_KEY_LEN];
    ac_dag_node_t *node;
    int rc;

    dag_make_key(key, type, id);

    ac_mutex_lock(&dag->lock);

    if (dag_find_node(dag, key)) {
        ac_mutex_unlock(&dag->lock);
        return AC_ERR_EXIST;
    }

    node = (ac_dag_node_t *)ac_zalloc(sizeof(*node), AC_MEM_NORMAL);
    if (!node) {
        ac_mutex_unlock(&dag->lock);
        return AC_ERR_NOMEM;
    }

    node->node_id.type = type;
    memcpy(node->node_id.id, id, AC_MAX_ADDR_LEN);

    rc = ac_hashmap_init(&node->children, 0, 0);
    if (rc != AC_OK) {
        ac_free(node);
        ac_mutex_unlock(&dag->lock);
        return rc;
    }

    rc = ac_hashmap_init(&node->parents, 0, 0);
    if (rc != AC_OK) {
        ac_hashmap_destroy(&node->children);
        ac_free(node);
        ac_mutex_unlock(&dag->lock);
        return rc;
    }

    rc = ac_hashmap_put(&dag->nodes, key, AC_DAG_KEY_LEN, node, NULL);
    if (rc != AC_OK) {
        dag_free_node(node);
        ac_mutex_unlock(&dag->lock);
        return rc;
    }

    dag->node_count++;
    dag->topo_valid = 0;

    ac_mutex_unlock(&dag->lock);
    return AC_OK;
}

int ac_dag_remove_node(ac_dag_t *dag, uint8_t type,
                       const uint8_t id[AC_MAX_ADDR_LEN])
{
    uint8_t key[AC_DAG_KEY_LEN];
    ac_dag_node_t *node;
    ac_hashmap_iter_t it;
    const void *parent_key;
    uint32_t parent_key_len;
    void *parent_val;

    dag_make_key(key, type, id);

    ac_mutex_lock(&dag->lock);

    node = dag_find_node(dag, key);
    if (!node) {
        ac_mutex_unlock(&dag->lock);
        return AC_ERR_NOENT;
    }

    /* Must have zero children (dependents) */
    if (ac_hashmap_count(&node->children) > 0) {
        ac_mutex_unlock(&dag->lock);
        return AC_ERR_EXIST;
    }

    /* S19: prune parent edges — remove this node from each parent's children */
    ac_hashmap_iter_init(&it, &node->parents);
    while (ac_hashmap_iter_next(&it, &parent_key, &parent_key_len,
                                &parent_val)) {
        ac_dag_node_t *parent_node = dag_find_node(
            dag, (const uint8_t *)parent_key);
        if (parent_node) {
            ac_hashmap_remove(&parent_node->children, key, AC_DAG_KEY_LEN);
            dag->edge_count--;
        }
    }

    /* Remove from nodes map and free */
    ac_hashmap_remove(&dag->nodes, key, AC_DAG_KEY_LEN);
    dag_free_node(node);
    dag->node_count--;
    dag->topo_valid = 0;

    ac_mutex_unlock(&dag->lock);
    return AC_OK;
}

int ac_dag_add_edge(ac_dag_t *dag,
                    uint8_t parent_type,
                    const uint8_t parent_id[AC_MAX_ADDR_LEN],
                    uint8_t child_type,
                    const uint8_t child_id[AC_MAX_ADDR_LEN])
{
    uint8_t parent_key[AC_DAG_KEY_LEN];
    uint8_t child_key[AC_DAG_KEY_LEN];
    ac_dag_node_t *parent_node;
    ac_dag_node_t *child_node;
    int rc;

    dag_make_key(parent_key, parent_type, parent_id);
    dag_make_key(child_key, child_type, child_id);

    ac_mutex_lock(&dag->lock);

    parent_node = dag_find_node(dag, parent_key);
    if (!parent_node) {
        ac_mutex_unlock(&dag->lock);
        return AC_ERR_NOENT;
    }

    child_node = dag_find_node(dag, child_key);
    if (!child_node) {
        ac_mutex_unlock(&dag->lock);
        return AC_ERR_NOENT;
    }

    /* Check if edge already exists */
    if (ac_hashmap_get(&parent_node->children, child_key, AC_DAG_KEY_LEN)) {
        ac_mutex_unlock(&dag->lock);
        return AC_ERR_EXIST;
    }

    /* S05: cycle detection — can child reach parent via children edges? */
    if (dag_dfs_reaches(dag, child_key, parent_key)) {
        ac_mutex_unlock(&dag->lock);
        return AC_ERR_INVAL;
    }

    /* Add child's key to parent's children map */
    rc = ac_hashmap_put(&parent_node->children, child_key, AC_DAG_KEY_LEN,
                        DAG_EDGE_MARKER, NULL);
    if (rc != AC_OK) {
        ac_mutex_unlock(&dag->lock);
        return rc;
    }

    /* Add parent's key to child's parents map */
    rc = ac_hashmap_put(&child_node->parents, parent_key, AC_DAG_KEY_LEN,
                        DAG_EDGE_MARKER, NULL);
    if (rc != AC_OK) {
        ac_hashmap_remove(&parent_node->children, child_key, AC_DAG_KEY_LEN);
        ac_mutex_unlock(&dag->lock);
        return rc;
    }

    dag->edge_count++;
    dag->topo_valid = 0;

    ac_mutex_unlock(&dag->lock);
    return AC_OK;
}

int ac_dag_remove_edge(ac_dag_t *dag,
                       uint8_t parent_type,
                       const uint8_t parent_id[AC_MAX_ADDR_LEN],
                       uint8_t child_type,
                       const uint8_t child_id[AC_MAX_ADDR_LEN])
{
    uint8_t parent_key[AC_DAG_KEY_LEN];
    uint8_t child_key[AC_DAG_KEY_LEN];
    ac_dag_node_t *parent_node;
    ac_dag_node_t *child_node;

    dag_make_key(parent_key, parent_type, parent_id);
    dag_make_key(child_key, child_type, child_id);

    ac_mutex_lock(&dag->lock);

    parent_node = dag_find_node(dag, parent_key);
    if (!parent_node) {
        ac_mutex_unlock(&dag->lock);
        return AC_ERR_NOENT;
    }

    child_node = dag_find_node(dag, child_key);
    if (!child_node) {
        ac_mutex_unlock(&dag->lock);
        return AC_ERR_NOENT;
    }

    if (!ac_hashmap_remove(&parent_node->children, child_key, AC_DAG_KEY_LEN)) {
        ac_mutex_unlock(&dag->lock);
        return AC_ERR_NOENT;
    }

    ac_hashmap_remove(&child_node->parents, parent_key, AC_DAG_KEY_LEN);

    dag->edge_count--;
    dag->topo_valid = 0;

    ac_mutex_unlock(&dag->lock);
    return AC_OK;
}

int ac_dag_has_dependents(ac_dag_t *dag, uint8_t type,
                          const uint8_t id[AC_MAX_ADDR_LEN])
{
    uint8_t key[AC_DAG_KEY_LEN];
    ac_dag_node_t *node;
    int result;

    dag_make_key(key, type, id);

    ac_mutex_lock(&dag->lock);

    node = dag_find_node(dag, key);
    result = node ? (ac_hashmap_count(&node->children) > 0 ? 1 : 0) : 0;

    ac_mutex_unlock(&dag->lock);
    return result;
}

uint32_t ac_dag_dependent_count(ac_dag_t *dag, uint8_t type,
                                const uint8_t id[AC_MAX_ADDR_LEN])
{
    uint8_t key[AC_DAG_KEY_LEN];
    ac_dag_node_t *node;
    uint32_t count;

    dag_make_key(key, type, id);

    ac_mutex_lock(&dag->lock);

    node = dag_find_node(dag, key);
    count = node ? ac_hashmap_count(&node->children) : 0;

    ac_mutex_unlock(&dag->lock);
    return count;
}

uint32_t ac_dag_node_count(ac_dag_t *dag)
{
    uint32_t count;

    ac_mutex_lock(&dag->lock);
    count = dag->node_count;
    ac_mutex_unlock(&dag->lock);

    return count;
}

uint32_t ac_dag_edge_count(ac_dag_t *dag)
{
    uint32_t count;

    ac_mutex_lock(&dag->lock);
    count = dag->edge_count;
    ac_mutex_unlock(&dag->lock);

    return count;
}

int ac_dag_would_cycle(ac_dag_t *dag,
                       uint8_t parent_type,
                       const uint8_t parent_id[AC_MAX_ADDR_LEN],
                       uint8_t child_type,
                       const uint8_t child_id[AC_MAX_ADDR_LEN])
{
    uint8_t parent_key[AC_DAG_KEY_LEN];
    uint8_t child_key[AC_DAG_KEY_LEN];
    int result;

    dag_make_key(parent_key, parent_type, parent_id);
    dag_make_key(child_key, child_type, child_id);

    ac_mutex_lock(&dag->lock);
    result = dag_dfs_reaches(dag, child_key, parent_key);
    ac_mutex_unlock(&dag->lock);

    return result;
}
