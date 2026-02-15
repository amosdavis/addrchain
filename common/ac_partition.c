/*
 * ac_partition.c — Network partition management implementation
 *
 * Manages PARTITION transactions: create/delete partitions, add/remove
 * subnets, allow/deny cross-partition traffic. Partitions enforce isolation
 * by default — cross-partition traffic is blocked unless explicitly allowed.
 *
 * Mitigates: N16,N22,N23
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

static ac_partition_record_t *find_mut(ac_partition_store_t *ps,
                                       const uint8_t id[AC_PARTITION_ID_LEN])
{
    uint32_t i;
    for (i = 0; i < ps->partition_count; i++) {
        if (ps->partitions[i].active &&
            id_eq(ps->partitions[i].partition_id, id, AC_PARTITION_ID_LEN))
            return &ps->partitions[i];
    }
    return NULL;
}

/* Find cross-rule index, or -1 */
static int find_cross_rule(const ac_partition_store_t *ps,
                           const uint8_t a[AC_PARTITION_ID_LEN],
                           const uint8_t b[AC_PARTITION_ID_LEN])
{
    uint32_t i;
    for (i = 0; i < ps->cross_rule_count; i++) {
        if ((id_eq(ps->cross_rules[i].partition_a, a, AC_PARTITION_ID_LEN) &&
             id_eq(ps->cross_rules[i].partition_b, b, AC_PARTITION_ID_LEN)) ||
            (id_eq(ps->cross_rules[i].partition_a, b, AC_PARTITION_ID_LEN) &&
             id_eq(ps->cross_rules[i].partition_b, a, AC_PARTITION_ID_LEN))) {
            return (int)i;
        }
    }
    return -1;
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
        /* VLAN ID uniqueness (N16) */
        if (pt->vlan_id != 0) {
            uint32_t i;
            for (i = 0; i < ps->partition_count; i++) {
                if (ps->partitions[i].active &&
                    ps->partitions[i].vlan_id == pt->vlan_id) {
                    ac_log(AC_LOG_WARN, "validate: VLAN ID %u already in use",
                           pt->vlan_id);
                    return AC_ERR_CONFLICT;
                }
            }
        }
        if (ps->partition_count >= AC_MAX_PARTITIONS) {
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
        if (rec->subnet_count >= AC_MAX_PARTITION_SUBNETS) {
            ac_log(AC_LOG_WARN, "validate: partition subnet list full");
            return AC_ERR_NOMEM;
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
            ps->cross_rule_count >= AC_MAX_CROSS_RULES) {
            ac_log(AC_LOG_WARN, "validate: cross-rule table full");
            return AC_ERR_NOMEM;
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
        rec = &ps->partitions[ps->partition_count];
        memset(rec, 0, sizeof(*rec));
        memcpy(rec->partition_id, pt->partition_id, AC_PARTITION_ID_LEN);
        rec->vlan_id = pt->vlan_id;
        memcpy(rec->creator, creator, AC_PUBKEY_LEN);
        rec->created_block = block_index;
        rec->active = 1;
        ps->partition_count++;
        ac_log(AC_LOG_INFO, "partition created: %.31s", pt->partition_id);
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
        if (rec && rec->subnet_count < AC_MAX_PARTITION_SUBNETS) {
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
                    /* Shift remaining entries */
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
            int idx = find_cross_rule(ps, pt->partition_id,
                                      pt->target_partition_id);
            if (idx >= 0) {
                ps->cross_rules[idx].allowed = 1;
            } else if (ps->cross_rule_count < AC_MAX_CROSS_RULES) {
                ac_cross_rule_t *rule = &ps->cross_rules[ps->cross_rule_count];
                memcpy(rule->partition_a, pt->partition_id, AC_PARTITION_ID_LEN);
                memcpy(rule->partition_b, pt->target_partition_id,
                       AC_PARTITION_ID_LEN);
                rule->allowed = 1;
                ps->cross_rule_count++;
            }
            ac_log(AC_LOG_INFO, "cross-partition traffic ALLOWED: %.31s <-> %.31s",
                   pt->partition_id, pt->target_partition_id);
        }
        break;

    case AC_PART_DENY_CROSS:
        {
            int idx = find_cross_rule(ps, pt->partition_id,
                                      pt->target_partition_id);
            if (idx >= 0) {
                ps->cross_rules[idx].allowed = 0;
                ac_log(AC_LOG_INFO, "cross-partition traffic DENIED: %.31s <-> %.31s",
                       pt->partition_id, pt->target_partition_id);
            }
        }
        break;

    default:
        break;
    }
}

/* ================================================================== */
/*  Public API                                                         */
/* ================================================================== */

int ac_partition_init(ac_partition_store_t *ps)
{
    if (!ps)
        return AC_ERR_INVAL;

    memset(ps, 0, sizeof(*ps));
    ac_mutex_init(&ps->lock);
    ac_log(AC_LOG_INFO, "partition store initialized");
    return AC_OK;
}

void ac_partition_destroy(ac_partition_store_t *ps)
{
    if (!ps)
        return;
    ac_mutex_destroy(&ps->lock);
    memset(ps, 0, sizeof(*ps));
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
    uint32_t i;
    if (!ps || !partition_id)
        return NULL;

    for (i = 0; i < ps->partition_count; i++) {
        if (ps->partitions[i].active &&
            id_eq(ps->partitions[i].partition_id, partition_id,
                  AC_PARTITION_ID_LEN))
            return &ps->partitions[i];
    }
    return NULL;
}

int ac_partition_allowed(const ac_partition_store_t *ps,
                         const uint8_t part_a[AC_PARTITION_ID_LEN],
                         const uint8_t part_b[AC_PARTITION_ID_LEN])
{
    int idx;
    if (!ps || !part_a || !part_b)
        return 0; /* deny by default */

    /* Same partition is always allowed */
    if (id_eq(part_a, part_b, AC_PARTITION_ID_LEN))
        return 1;

    idx = find_cross_rule(ps, part_a, part_b);
    if (idx >= 0)
        return ps->cross_rules[idx].allowed;

    return 0; /* deny by default (N22) */
}

const ac_partition_record_t *ac_partition_for_subnet(
    const ac_partition_store_t *ps,
    const uint8_t subnet_id[AC_SUBNET_ID_LEN])
{
    uint32_t i, j;
    if (!ps || !subnet_id)
        return NULL;

    for (i = 0; i < ps->partition_count; i++) {
        if (!ps->partitions[i].active)
            continue;
        for (j = 0; j < ps->partitions[i].subnet_count; j++) {
            if (id_eq(ps->partitions[i].subnet_ids[j], subnet_id,
                      AC_SUBNET_ID_LEN))
                return &ps->partitions[i];
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

    ps->partition_count = 0;
    ps->cross_rule_count = 0;
    memset(ps->partitions, 0, sizeof(ps->partitions));
    memset(ps->cross_rules, 0, sizeof(ps->cross_rules));

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
    ac_log(AC_LOG_INFO, "partition store rebuilt: %u partitions, %u cross-rules",
           ps->partition_count, ps->cross_rule_count);
    return AC_OK;
}
