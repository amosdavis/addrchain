/*
 * ac_subnet.h — Subnet management interface (dynamic hashmap-backed)
 *
 * Manages SUBNET_CREATE and SUBNET_ASSIGN transactions. Validates prefix
 * membership, detects overlapping subnets, and tracks node-to-subnet
 * assignments. Backed by ac_hashmap_t for unlimited scaling.
 *
 * Mitigates: N02,N05,N11,N12,N13,N14,N15,N20,N29,N31,S01,S15
 */

#ifndef AC_SUBNET_H
#define AC_SUBNET_H

#include "ac_proto.h"
#include "ac_platform.h"
#include "ac_hashmap.h"
#include "ac_dag.h"

/* ------------------------------------------------------------------ */
/*  Subnet record                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t             subnet_id[AC_SUBNET_ID_LEN];
    ac_address_t        prefix;
    ac_address_t        gateway;
    ac_address_t        dns[AC_MAX_DNS_ADDRS];
    uint8_t             dns_count;
    uint16_t            vlan_id;
    uint8_t             flags;          /* AC_SUBNET_FLAG_* */
    uint8_t             creator[AC_PUBKEY_LEN];
    uint32_t            created_block;  /* block index of SUBNET_CREATE */
    uint8_t             active;         /* 1 = active, 0 = deleted */
} ac_subnet_record_t;

/* Node-to-subnet assignment */
typedef struct {
    uint8_t     node_pubkey[AC_PUBKEY_LEN];
    uint8_t     subnet_id[AC_SUBNET_ID_LEN];
    uint32_t    assigned_block;
} ac_subnet_member_t;

/* Member composite key: pubkey(32) + subnet_id(32) = 64 bytes */
#define AC_MEMBER_KEY_LEN (AC_PUBKEY_LEN + AC_SUBNET_ID_LEN)

/* ------------------------------------------------------------------ */
/*  Subnet store                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    ac_hashmap_t        subnet_map;     /* keyed by subnet_id */
    uint32_t            subnet_count;
    uint32_t            max_subnets;

    ac_hashmap_t        member_map;     /* keyed by pubkey+subnet_id */
    uint32_t            member_count;
    uint32_t            max_members;

    ac_mutex_t          lock;
    ac_dag_t           *dag;            /* optional DAG for dependency tracking */
} ac_subnet_store_t;

/* ------------------------------------------------------------------ */
/*  API                                                                */
/* ------------------------------------------------------------------ */

/*
 * ac_subnet_init — Initialize the subnet store.
 * max_subnets/max_members: 0 = unlimited (userspace), >0 = capped (kernel).
 * Returns AC_OK on success.
 */
int ac_subnet_init(ac_subnet_store_t *ss,
                   uint32_t max_subnets, uint32_t max_members,
                   ac_dag_t *dag);

/*
 * ac_subnet_destroy — Free subnet store resources.
 */
void ac_subnet_destroy(ac_subnet_store_t *ss);

/*
 * ac_subnet_validate_block — Validate all subnet-related txs in a block
 *                            against current state. Does not modify state.
 * Returns AC_OK if all txs are valid.
 */
int ac_subnet_validate_block(ac_subnet_store_t *ss,
                             const ac_block_t *blk);

/*
 * ac_subnet_apply_block — Apply a validated block's subnet txs to state.
 * Returns AC_OK on success.
 */
int ac_subnet_apply_block(ac_subnet_store_t *ss,
                          const ac_block_t *blk);

/*
 * ac_subnet_find — Look up a subnet by ID.
 * Returns pointer to record, or NULL if not found.
 */
const ac_subnet_record_t *ac_subnet_find(const ac_subnet_store_t *ss,
                                         const uint8_t subnet_id[AC_SUBNET_ID_LEN]);

/*
 * ac_subnet_contains — Check if an address falls within a subnet's prefix.
 * Returns 1 if the address is within the subnet, 0 otherwise.
 */
int ac_subnet_contains(const ac_subnet_record_t *subnet,
                       const ac_address_t *addr);

/*
 * ac_subnet_overlaps — Check if two prefixes overlap.
 * Returns 1 if they overlap, 0 otherwise.
 */
int ac_subnet_overlaps(const ac_address_t *a, const ac_address_t *b);

/*
 * ac_subnet_is_member — Check if a node is assigned to a subnet.
 * Returns 1 if assigned, 0 otherwise.
 */
int ac_subnet_is_member(const ac_subnet_store_t *ss,
                        const uint8_t node_pubkey[AC_PUBKEY_LEN],
                        const uint8_t subnet_id[AC_SUBNET_ID_LEN]);

/*
 * ac_subnet_count — Number of active subnets.
 */
uint32_t ac_subnet_count(const ac_subnet_store_t *ss);

/*
 * ac_subnet_member_count — Number of subnet assignments.
 */
uint32_t ac_subnet_member_count(const ac_subnet_store_t *ss);

/*
 * ac_subnet_rebuild — Rebuild subnet state from a chain of blocks.
 * Returns AC_OK on success.
 */
int ac_subnet_rebuild(ac_subnet_store_t *ss,
                      const ac_block_t *blocks,
                      uint32_t block_count);

#endif /* AC_SUBNET_H */
