/*
 * ac_partition.c — Network partition management implementation
 *
 * Manages PARTITION transactions: create/delete partitions, add/remove
 * subnets, allow/deny cross-partition traffic. Partitions enforce isolation
 * by default — cross-partition traffic is blocked unless explicitly allowed.
 *
 * Backed by ac_hashmap_t for dynamic scaling (S27).
 *
 * Mitigates: N16,N22,N23,S27
 */

#include "ac_partition.h"
#include "ac_chain.h"

#include <string.h>

/* ================================================================== */
/*  Internal helpers                                                   */
/* ================================================================== */

static int id_eq(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    return memcmp(a, b, len) == 0;
}

static uint32_t id_slen(const uint8_t *id, uint32_t max)
{
    uint32_t i;
    for (i = 0; i < max; i++) {
        if (id[i] == 0)
            return i;
    }
    return max;
}

/* Build canonical cross-rule key: always store smaller ID first */
static void make_cross_key(uint8_t key[AC_CROSS_RULE_KEY_LEN],
                           const uint8_t a[AC_PARTITION_ID_LEN],
                           const uint8_t b[AC_PARTITION_ID_LEN])
{
    if (memcmp(a, b, AC_PARTITION_ID_LEN) <= 0) {
        memcpy(key, a, AC_PARTITION_ID_LEN);
        memcpy(key + AC_PARTITION_ID_LEN, b, AC_PARTITION_ID_LEN);
    } else {
        memcpy(key, b, AC_PARTITION_ID_LEN);
        memcpy(key + AC_PARTITION_ID_LEN, a, AC_PARTITION_ID_LEN);
    }
}

/* Find mutable partition record via hashmap */
static ac_partition_record_t *find_mut(ac_partition_store_t *ps,
                                       const uint8_t id[AC_PARTITION_ID_LEN])
{
    ac_partition_record_t *rec;
    rec = (ac_partition_record_t *)ac_hashmap_get(&ps->partition_map,
                                                   id, AC_PARTITION_ID_LEN);
    if (rec && rec->active)
        return rec;
    return NULL;
}

/* Find cross-rule by composite key (canonical order handles both orderings) */
static ac_cross_rule_t *find_cross_rule(const ac_partition_store_t *ps,
                                        const uint8_t a[AC_PARTITION_ID_LEN],
                                        const uint8_t b[AC_PARTITION_ID_LEN])
{
    uint8_t key[AC_CROSS_RULE_KEY_LEN];
    make_cross_key(key, a, b);
    return (ac_cross_rule_t *)ac_hashmap_get(&ps->cross_rule_map,
                                              key, AC_CROSS_RULE_KEY_LEN);
}

/* Grow the subnet_ids dynamic array (alloc new, copy, free old) */
static int grow_subnet_ids(ac_partition_record_t *rec)
{
    uint32_t new_cap = rec->subnet_capacity * 2;
    uint8_t (*new_ids)[AC_SUBNET_ID_LEN];

    if (new_cap == 0)
        new_cap = AC_PARTITION_SUBNET_INIT_CAP;

    new_ids = ac_zalloc(new_cap * AC_SUBNET_ID_LEN, AC_MEM_NORMAL);
    if (!new_ids)
        return AC_ERR_NOMEM;

    if (rec->subnet_ids) {
        memcpy(new_ids, rec->subnet_ids,
               rec->subnet_count * AC_SUBNET_ID_LEN);
        ac_free(rec->subnet_ids);
    }

    rec->subnet_ids = new_ids;
    rec->subnet_capacity = new_cap;
    return AC_OK;
}

/* ================================================================== */
/*  Validation                                                         */
/* ================================================================== */

static int validate_partition_tx(const ac_partition_store_t *ps,
                                 const ac_tx_partition_t *pt)
{
    const ac_partition_record_t *rec;

    if (id_slen(pt->partition_id, AC_PARTITION_ID_LEN) == 0) {
        ac_log(AC_LOG_WARN, "validate: empty partition_id");
        return AC_ERR_INVAL;
    }

    switch (pt->action) {
    case AC_PART_CREATE:
        /* Must not already exist */
        if (find_mut((ac_partition_store_t *)ps, pt->partition_id) != NULL) {
            ac_log(AC_LOG_WARN, "validate: partition already exists");
            return AC_ERR_EXIST;
        }
        /* VLAN ID uniqueness (N16): iterate partition_map */
        if (pt->vlan_id != 0) {
            ac_hashmap_iter_t vit;
            const void *vk;
            uint32_t vkl;
            void *vv;
            ac_hashmap_iter_init(&vit, (ac_hashmap_t *)&ps->partition_map);
            while (ac_hashmap_iter_next(&vit, &vk, &vkl, &vv)) {
                ac_partition_record_t *p = (ac_partition_record_t *)vv;
                if (p->active && p->vlan_id == pt->vlan_id) {
                    ac_log(AC_LOG_WARN,
                           "validate: VLAN ID %u already in use",
                           pt->vlan_id);
                    return AC_ERR_CONFLICT;
                }
            }
        }
        if (ps->max_partitions > 0 &&
            ps->partition_count >= ps->max_partitions) {
            ac_log(AC_LOG_WARN, "validate: partition table full");
            return AC_ERR_NOMEM;
        }
        break;

    case AC_PART_DELETE:
        rec = ac_partition_find(ps, pt->partition_id);
        if (!rec) {
            ac_log(AC_LOG_WARN, "validate: partition not found for DELETE");
            return AC_ERR_NOENT;
        }
        break;

    case AC_PART_ADD_SUBNET:
        rec = ac_partition_find(ps, pt->partition_id);
        if (!rec) {
            ac_log(AC_LOG_WARN, "validate: partition not found for ADD_SUBNET");
            return AC_ERR_NOENT;
        }
        /* Check subnet not already in this partition */
        {
            uint32_t i;
            for (i = 0; i < rec->subnet_count; i++) {
                if (id_eq(rec->subnet_ids[i], pt->target_subnet_id,
                          AC_SUBNET_ID_LEN)) {
                    ac_log(AC_LOG_WARN, "validate: subnet already in partition");
                    return AC_ERR_EXIST;
                }
            }
        }
        break;

    case AC_PART_REMOVE_SUBNET:
        rec = ac_partition_find(ps, pt->partition_id);
        if (!rec) {
            ac_log(AC_LOG_WARN, "validate: partition not found for REMOVE_SUBNET");
            return AC_ERR_NOENT;
        }
        {
            uint32_t i;
            int found = 0;
            for (i = 0; i < rec->subnet_count; i++) {
                if (id_eq(rec->subnet_ids[i], pt->target_subnet_id,
                          AC_SUBNET_ID_LEN)) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                ac_log(AC_LOG_WARN, "validate: subnet not in partition");
                return AC_ERR_NOENT;
            }
        }
        break;

    case AC_PART_ALLOW_CROSS:
    case AC_PART_DENY_CROSS:
        /* Both partitions must exist */
        if (!ac_partition_find(ps, pt->partition_id)) {
            ac_log(AC_LOG_WARN, "validate: source partition not found");
            return AC_ERR_NOENT;
        }
        if (id_slen(pt->target_partition_id, AC_PARTITION_ID_LEN) == 0) {
            ac_log(AC_LOG_WARN, "validate: empty target_partition_id");
            return AC_ERR_INVAL;
        }
        if (!ac_partition_find(ps, pt->target_partition_id)) {
            ac_log(AC_LOG_WARN, "validate: target partition not found");
            return AC_ERR_NOENT;
        }
        if (pt->action == AC_PART_ALLOW_CROSS &&
            ps->max_cross_rules > 0 &&
            ps->cross_rule_count >= ps->max_cross_rules) {
            /* Only reject if rule doesn't already exist */
            if (!find_cross_rule(ps, pt->partition_id,
                                  pt->target_partition_id)) {
                ac_log(AC_LOG_WARN, "validate: cross-rule table full");
                return AC_ERR_NOMEM;
            }
        }
        break;

    default:
        ac_log(AC_LOG_WARN, "validate: unknown partition action %u", pt->action);
        return AC_ERR_INVAL;
    }

    return AC_OK;
}

/* ================================================================== */
/*  Apply                                                              */
/* ================================================================== */

static void apply_partition_tx(ac_partition_store_t *ps,
                               const ac_tx_partition_t *pt,
                               const uint8_t *creator,
                               uint32_t block_index)
{
    ac_partition_record_t *rec;

    switch (pt->action) {
    case AC_PART_CREATE:
        {
            rec = (ac_partition_record_t *)ac_zalloc(sizeof(*rec),
                                                      AC_MEM_NORMAL);
            if (!rec) {
                ac_log(AC_LOG_ERROR, "partition alloc failed");
                return;
            }
            memcpy(rec->partition_id, pt->partition_id, AC_PARTITION_ID_LEN);
            rec->vlan_id = pt->vlan_id;
            memcpy(rec->creator, creator, AC_PUBKEY_LEN);
            rec->created_block = block_index;
            rec->active = 1;
            rec->subnet_ids = NULL;
            rec->subnet_count = 0;
            rec->subnet_capacity = 0;

            if (ac_hashmap_put(&ps->partition_map, pt->partition_id,
                               AC_PARTITION_ID_LEN, rec, NULL) != AC_OK) {
                ac_free(rec);
                ac_log(AC_LOG_ERROR, "partition hashmap put failed");
                return;
            }
            ps->partition_count++;
            ac_log(AC_LOG_INFO, "partition created: %.31s", pt->partition_id);
        }
        break;

    case AC_PART_DELETE:
        rec = find_mut(ps, pt->partition_id);
        if (rec) {
            rec->active = 0;
            ac_log(AC_LOG_INFO, "partition deleted: %.31s", pt->partition_id);
        }
        break;

    case AC_PART_ADD_SUBNET:
        rec = find_mut(ps, pt->partition_id);
        if (rec) {
            if (rec->subnet_count >= rec->subnet_capacity) {
                if (grow_subnet_ids(rec) != AC_OK) {
                    ac_log(AC_LOG_ERROR, "subnet array grow failed");
                    return;
                }
            }
            memcpy(rec->subnet_ids[rec->subnet_count],
                   pt->target_subnet_id, AC_SUBNET_ID_LEN);
            rec->subnet_count++;
            ac_log(AC_LOG_INFO, "subnet added to partition %.31s",
                   pt->partition_id);
        }
        break;

    case AC_PART_REMOVE_SUBNET:
        rec = find_mut(ps, pt->partition_id);
        if (rec) {
            uint32_t i;
            for (i = 0; i < rec->subnet_count; i++) {
                if (id_eq(rec->subnet_ids[i], pt->target_subnet_id,
                          AC_SUBNET_ID_LEN)) {
                    if (i < rec->subnet_count - 1) {
                        memmove(rec->subnet_ids[i], rec->subnet_ids[i + 1],
                                (rec->subnet_count - 1 - i) * AC_SUBNET_ID_LEN);
                    }
                    rec->subnet_count--;
                    ac_log(AC_LOG_INFO, "subnet removed from partition %.31s",
                           pt->partition_id);
                    break;
                }
            }
        }
        break;

    case AC_PART_ALLOW_CROSS:
        {
            ac_cross_rule_t *rule = find_cross_rule(ps, pt->partition_id,
                                                     pt->target_partition_id);
            if (rule) {
                rule->allowed = 1;
            } else {
                uint8_t key[AC_CROSS_RULE_KEY_LEN];
                rule = (ac_cross_rule_t *)ac_zalloc(sizeof(*rule),
                                                     AC_MEM_NORMAL);
                if (!rule) {
                    ac_log(AC_LOG_ERROR, "cross-rule alloc failed");
                    return;
                }
                memcpy(rule->partition_a, pt->partition_id,
                       AC_PARTITION_ID_LEN);
                memcpy(rule->partition_b, pt->target_partition_id,
                       AC_PARTITION_ID_LEN);
                rule->allowed = 1;
                make_cross_key(key, pt->partition_id,
                               pt->target_partition_id);
                if (ac_hashmap_put(&ps->cross_rule_map, key,
                                   AC_CROSS_RULE_KEY_LEN,
                                   rule, NULL) != AC_OK) {
                    ac_free(rule);
                    ac_log(AC_LOG_ERROR, "cross-rule hashmap put failed");
                    return;
                }
                ps->cross_rule_count++;
            }
            ac_log(AC_LOG_INFO,
                   "cross-partition traffic ALLOWED: %.31s <-> %.31s",
                   pt->partition_id, pt->target_partition_id);
        }
        break;

    case AC_PART_DENY_CROSS:
        {
            ac_cross_rule_t *rule = find_cross_rule(ps, pt->partition_id,
                                                     pt->target_partition_id);
            if (rule) {
                rule->allowed = 0;
                ac_log(AC_LOG_INFO,
                       "cross-partition traffic DENIED: %.31s <-> %.31s",
                       pt->partition_id, pt->target_partition_id);
            }
        }
        break;

    default:
        break;
    }
}

/* ================================================================== */
/*  Free helpers                                                       */
/* ================================================================== */

static void free_all_partitions(ac_partition_store_t *ps)
{
    ac_hashmap_iter_t it;
    const void *k;
    uint32_t kl;
    void *v;

    ac_hashmap_iter_init(&it, &ps->partition_map);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v)) {
        ac_partition_record_t *rec = (ac_partition_record_t *)v;
        if (rec->subnet_ids)
            ac_free(rec->subnet_ids);
        ac_free(rec);
    }
}

static void free_all_cross_rules(ac_partition_store_t *ps)
{
    ac_hashmap_iter_t it;
    const void *k;
    uint32_t kl;
    void *v;

    ac_hashmap_iter_init(&it, &ps->cross_rule_map);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v))
        ac_free(v);
}

/* ================================================================== */
/*  Public API                                                         */
/* ================================================================== */

int ac_partition_init(ac_partition_store_t *ps,
                      uint32_t max_partitions,
                      uint32_t max_cross_rules)
{
    int rc;

    if (!ps)
        return AC_ERR_INVAL;

    memset(ps, 0, sizeof(*ps));

    rc = ac_mutex_init(&ps->lock);
    if (rc != AC_OK)
        return rc;

    ps->max_partitions = max_partitions;
    ps->max_cross_rules = max_cross_rules;

    rc = ac_hashmap_init(&ps->partition_map, 64, max_partitions);
    if (rc != AC_OK) {
        ac_mutex_destroy(&ps->lock);
        return rc;
    }

    rc = ac_hashmap_init(&ps->cross_rule_map, 64, max_cross_rules);
    if (rc != AC_OK) {
        ac_hashmap_destroy(&ps->partition_map);
        ac_mutex_destroy(&ps->lock);
        return rc;
    }

    ac_log(AC_LOG_INFO, "partition store initialized");
    return AC_OK;
}

void ac_partition_destroy(ac_partition_store_t *ps)
{
    if (!ps)
        return;

    ac_mutex_lock(&ps->lock);

    free_all_partitions(ps);
    ac_hashmap_destroy(&ps->partition_map);

    free_all_cross_rules(ps);
    ac_hashmap_destroy(&ps->cross_rule_map);

    ps->partition_count = 0;
    ps->cross_rule_count = 0;

    ac_mutex_unlock(&ps->lock);
    ac_mutex_destroy(&ps->lock);
    ac_log(AC_LOG_INFO, "partition store destroyed");
}

int ac_partition_validate_block(ac_partition_store_t *ps,
                                const ac_block_t *blk)
{
    uint16_t i;
    int rc;

    if (!ps || !blk)
        return AC_ERR_INVAL;

    ac_mutex_lock(&ps->lock);

    for (i = 0; i < blk->tx_count; i++) {
        const ac_transaction_t *tx = &blk->txs[i];
        if (tx->type == AC_TX_PARTITION) {
            rc = validate_partition_tx(ps, &tx->payload.partition);
            if (rc != AC_OK) {
                ac_mutex_unlock(&ps->lock);
                return rc;
            }
        }
    }

    ac_mutex_unlock(&ps->lock);
    return AC_OK;
}

int ac_partition_apply_block(ac_partition_store_t *ps,
                             const ac_block_t *blk)
{
    uint16_t i;

    if (!ps || !blk)
        return AC_ERR_INVAL;

    ac_mutex_lock(&ps->lock);

    for (i = 0; i < blk->tx_count; i++) {
        const ac_transaction_t *tx = &blk->txs[i];
        if (tx->type == AC_TX_PARTITION)
            apply_partition_tx(ps, &tx->payload.partition,
                               tx->node_pubkey, blk->index);
    }

    ac_mutex_unlock(&ps->lock);
    return AC_OK;
}

const ac_partition_record_t *ac_partition_find(
    const ac_partition_store_t *ps,
    const uint8_t partition_id[AC_PARTITION_ID_LEN])
{
    ac_partition_record_t *rec;

    if (!ps || !partition_id)
        return NULL;

    rec = (ac_partition_record_t *)ac_hashmap_get(&ps->partition_map,
                                                   partition_id,
                                                   AC_PARTITION_ID_LEN);
    if (rec && rec->active)
        return rec;
    return NULL;
}

int ac_partition_allowed(const ac_partition_store_t *ps,
                         const uint8_t part_a[AC_PARTITION_ID_LEN],
                         const uint8_t part_b[AC_PARTITION_ID_LEN])
{
    ac_cross_rule_t *rule;

    if (!ps || !part_a || !part_b)
        return 0;

    /* Same partition is always allowed */
    if (id_eq(part_a, part_b, AC_PARTITION_ID_LEN))
        return 1;

    rule = find_cross_rule(ps, part_a, part_b);
    if (rule)
        return rule->allowed;

    return 0; /* deny by default (N22) */
}

const ac_partition_record_t *ac_partition_for_subnet(
    const ac_partition_store_t *ps,
    const uint8_t subnet_id[AC_SUBNET_ID_LEN])
{
    ac_hashmap_iter_t it;
    const void *k;
    uint32_t kl;
    void *v;

    if (!ps || !subnet_id)
        return NULL;

    ac_hashmap_iter_init(&it, (ac_hashmap_t *)&ps->partition_map);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v)) {
        ac_partition_record_t *rec = (ac_partition_record_t *)v;
        uint32_t j;
        if (!rec->active)
            continue;
        for (j = 0; j < rec->subnet_count; j++) {
            if (id_eq(rec->subnet_ids[j], subnet_id, AC_SUBNET_ID_LEN))
                return rec;
        }
    }
    return NULL;
}

uint32_t ac_partition_count(const ac_partition_store_t *ps)
{
    if (!ps)
        return 0;
    return ps->partition_count;
}

int ac_partition_rebuild(ac_partition_store_t *ps,
                         const ac_block_t *blocks,
                         uint32_t block_count)
{
    uint32_t i;

    if (!ps || (!blocks && block_count > 0))
        return AC_ERR_INVAL;

    ac_mutex_lock(&ps->lock);

    /* Free existing records and clear hashmaps */
    free_all_partitions(ps);
    ac_hashmap_destroy(&ps->partition_map);

    free_all_cross_rules(ps);
    ac_hashmap_destroy(&ps->cross_rule_map);

    ps->partition_count = 0;
    ps->cross_rule_count = 0;

    ac_hashmap_init(&ps->partition_map, 64, ps->max_partitions);
    ac_hashmap_init(&ps->cross_rule_map, 64, ps->max_cross_rules);

    /* Replay all blocks */
    for (i = 0; i < block_count; i++) {
        uint16_t j;
        const ac_block_t *blk = &blocks[i];

        for (j = 0; j < blk->tx_count; j++) {
            const ac_transaction_t *tx = &blk->txs[j];
            if (tx->type == AC_TX_PARTITION)
                apply_partition_tx(ps, &tx->payload.partition,
                                   tx->node_pubkey, blk->index);
        }
    }

    ac_mutex_unlock(&ps->lock);
    ac_log(AC_LOG_INFO,
           "partition store rebuilt: %u partitions, %u cross-rules",
           ps->partition_count, ps->cross_rule_count);
    return AC_OK;
}
