/*
 * ac_partition.h — Network partition management interface
 *
 * Manages PARTITION transactions: create/delete partitions, add/remove
 * subnets, allow/deny cross-partition traffic. Partitions are named groups
 * of subnets with enforced isolation.
 *
 * Backed by ac_hashmap_t for dynamic scaling (S27).
 *
 * Mitigates: N16,N22,N23,S27
 */

#ifndef AC_PARTITION_H
#define AC_PARTITION_H

#include "ac_proto.h"
#include "ac_platform.h"
#include "ac_hashmap.h"

/* ------------------------------------------------------------------ */
/*  Limits (legacy constants removed; now dynamic via hashmap)         */
/* ------------------------------------------------------------------ */

/* Removed: AC_MAX_PARTITIONS, AC_MAX_PARTITION_SUBNETS, AC_MAX_CROSS_RULES
 * — now dynamic via hashmap */

#define AC_PARTITION_SUBNET_INIT_CAP  8  /* initial subnet_ids capacity */

/* ------------------------------------------------------------------ */
/*  Partition record                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t     partition_id[AC_PARTITION_ID_LEN];
    uint16_t    vlan_id;
    uint8_t     creator[AC_PUBKEY_LEN];
    uint32_t    created_block;
    uint8_t     active;

    /* Dynamic array of subnets belonging to this partition (S27) */
    uint8_t     (*subnet_ids)[AC_SUBNET_ID_LEN];
    uint32_t    subnet_count;
    uint32_t    subnet_capacity;
} ac_partition_record_t;

/* Cross-partition traffic rule */
typedef struct {
    uint8_t     partition_a[AC_PARTITION_ID_LEN];
    uint8_t     partition_b[AC_PARTITION_ID_LEN];
    uint8_t     allowed;    /* 1 = allowed, 0 = denied */
} ac_cross_rule_t;

/* Composite key for cross-rule lookup: partition_a + partition_b */
#define AC_CROSS_RULE_KEY_LEN  (AC_PARTITION_ID_LEN * 2)

/* ------------------------------------------------------------------ */
/*  Partition store                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    ac_hashmap_t    partition_map;   /* key: partition_id → ac_partition_record_t* */
    uint32_t        partition_count;

    ac_hashmap_t    cross_rule_map;  /* key: partition_a+partition_b → ac_cross_rule_t* */
    uint32_t        cross_rule_count;

    uint32_t        max_partitions;  /* 0 = unlimited (userspace) */
    uint32_t        max_cross_rules; /* 0 = unlimited (userspace) */

    ac_mutex_t      lock;
} ac_partition_store_t;

/* ------------------------------------------------------------------ */
/*  API                                                                */
/* ------------------------------------------------------------------ */

int ac_partition_init(ac_partition_store_t *ps,
                      uint32_t max_partitions,
                      uint32_t max_cross_rules);
void ac_partition_destroy(ac_partition_store_t *ps);

int ac_partition_validate_block(ac_partition_store_t *ps,
                                const ac_block_t *blk);

int ac_partition_apply_block(ac_partition_store_t *ps,
                             const ac_block_t *blk);

const ac_partition_record_t *ac_partition_find(
    const ac_partition_store_t *ps,
    const uint8_t partition_id[AC_PARTITION_ID_LEN]);

/*
 * ac_partition_allowed — Check if traffic between two partitions is allowed.
 * Default is DENIED (isolation). Only explicit ALLOW_CROSS allows traffic.
 */
int ac_partition_allowed(const ac_partition_store_t *ps,
                         const uint8_t part_a[AC_PARTITION_ID_LEN],
                         const uint8_t part_b[AC_PARTITION_ID_LEN]);

/*
 * ac_partition_for_subnet — Find which partition a subnet belongs to.
 * Returns pointer to partition record, or NULL.
 */
const ac_partition_record_t *ac_partition_for_subnet(
    const ac_partition_store_t *ps,
    const uint8_t subnet_id[AC_SUBNET_ID_LEN]);

uint32_t ac_partition_count(const ac_partition_store_t *ps);

int ac_partition_rebuild(ac_partition_store_t *ps,
                         const ac_block_t *blocks,
                         uint32_t block_count);

#endif /* AC_PARTITION_H */
