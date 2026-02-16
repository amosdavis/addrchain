/*
 * ac_dag.h — Directed Acyclic Graph dependency tracking for addrchain
 *
 * Tracks resource dependencies (subnet, claim, VPN tunnel, partition)
 * as a DAG. Cycle detection via iterative DFS (K06: no recursion).
 * Thread-safe: all public functions acquire dag->lock internally.
 *
 * Mitigates: S05 (cycle detection), S19 (prune on remove),
 *            S21 (topo cache invalidation), K06 (no recursion)
 */

#ifndef AC_DAG_H
#define AC_DAG_H

#include "ac_proto.h"
#include "ac_platform.h"
#include "ac_hashmap.h"

/* ------------------------------------------------------------------ */
/*  Resource types tracked by DAG                                      */
/* ------------------------------------------------------------------ */

typedef enum {
    AC_RES_SUBNET      = 0x01,
    AC_RES_CLAIM       = 0x02,
    AC_RES_VPN_TUNNEL  = 0x03,
    AC_RES_PARTITION   = 0x04,
} ac_resource_type_t;

/* ------------------------------------------------------------------ */
/*  DAG key: type(1) + id(32) = 33 bytes                               */
/* ------------------------------------------------------------------ */

#define AC_DAG_KEY_LEN  33  /* 1 byte type + 32 bytes id */

typedef struct {
    uint8_t     type;                       /* ac_resource_type_t */
    uint8_t     id[AC_MAX_ADDR_LEN];        /* resource identifier */
} ac_dag_node_id_t;

/* ------------------------------------------------------------------ */
/*  DAG node: represents a network resource                            */
/* ------------------------------------------------------------------ */

typedef struct {
    ac_dag_node_id_t    node_id;
    ac_hashmap_t        children;   /* dependents: things that depend on this */
    ac_hashmap_t        parents;    /* dependencies: things this depends on */
} ac_dag_node_t;

/* ------------------------------------------------------------------ */
/*  DAG container                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    ac_hashmap_t    nodes;          /* key=dag_key(type+id) -> ac_dag_node_t* */
    uint32_t        node_count;
    uint32_t        edge_count;
    ac_mutex_t      lock;
    uint8_t         topo_valid;     /* 1 if cached topo order is current (S21) */
} ac_dag_t;

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                          */
/* ------------------------------------------------------------------ */

int  ac_dag_init(ac_dag_t *dag);
void ac_dag_destroy(ac_dag_t *dag);

/* ------------------------------------------------------------------ */
/*  Node operations                                                    */
/* ------------------------------------------------------------------ */

/* Add a node (no edges). Returns AC_ERR_EXIST if already present. */
int ac_dag_add_node(ac_dag_t *dag, uint8_t type,
                    const uint8_t id[AC_MAX_ADDR_LEN]);

/* Remove a node. Fails with AC_ERR_EXIST if it has dependents (children).
 * Also removes all edges where this node is a child (parent edges).
 * S19: prune on remove. */
int ac_dag_remove_node(ac_dag_t *dag, uint8_t type,
                       const uint8_t id[AC_MAX_ADDR_LEN]);

/* ------------------------------------------------------------------ */
/*  Edge operations                                                    */
/* ------------------------------------------------------------------ */

/* Add directed edge: child depends on parent.
 * Both nodes must exist. Checks for cycles (S05).
 * Returns AC_ERR_INVAL if would create cycle. */
int ac_dag_add_edge(ac_dag_t *dag,
                    uint8_t parent_type,
                    const uint8_t parent_id[AC_MAX_ADDR_LEN],
                    uint8_t child_type,
                    const uint8_t child_id[AC_MAX_ADDR_LEN]);

/* Remove edge. Returns AC_ERR_NOENT if not found. */
int ac_dag_remove_edge(ac_dag_t *dag,
                       uint8_t parent_type,
                       const uint8_t parent_id[AC_MAX_ADDR_LEN],
                       uint8_t child_type,
                       const uint8_t child_id[AC_MAX_ADDR_LEN]);

/* ------------------------------------------------------------------ */
/*  Queries                                                            */
/* ------------------------------------------------------------------ */

/* Does this node have any dependents (children)? */
int ac_dag_has_dependents(ac_dag_t *dag, uint8_t type,
                          const uint8_t id[AC_MAX_ADDR_LEN]);

/* Count of dependents */
uint32_t ac_dag_dependent_count(ac_dag_t *dag, uint8_t type,
                                const uint8_t id[AC_MAX_ADDR_LEN]);

/* Get node/edge counts */
uint32_t ac_dag_node_count(ac_dag_t *dag);
uint32_t ac_dag_edge_count(ac_dag_t *dag);

/* Check if adding edge would create a cycle. Returns 1 if cycle, 0 if safe.
 * Uses iterative DFS from child to see if it can reach parent (K06). */
int ac_dag_would_cycle(ac_dag_t *dag,
                       uint8_t parent_type,
                       const uint8_t parent_id[AC_MAX_ADDR_LEN],
                       uint8_t child_type,
                       const uint8_t child_id[AC_MAX_ADDR_LEN]);

#endif /* AC_DAG_H */
