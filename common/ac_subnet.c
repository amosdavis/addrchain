/*
 * ac_subnet.c — Subnet management implementation (dynamic hashmap-backed)
 *
 * Manages SUBNET_CREATE / SUBNET_ASSIGN transactions. Validates prefix
 * membership, detects overlapping subnets, enforces gateway/DNS requirements,
 * and tracks node-to-subnet assignments.
 * Backed by ac_hashmap_t for unlimited scaling.
 *
 * Mitigates: N02,N05,N11,N12,N13,N14,N15,N20,N29,N31,S01,S15
 */

#include "ac_subnet.h"
#include "ac_chain.h"
#include "ac_crypto.h"

#include <string.h>

/* ================================================================== */
/*  Internal helpers                                                   */
/* ================================================================== */

static uint32_t id_len(const uint8_t *id, uint32_t max)
{
    uint32_t i;
    for (i = 0; i < max; i++) {
        if (id[i] == 0)
            return i;
    }
    return max;
}

static uint16_t addr_max_bits(uint8_t family)
{
    switch (family) {
    case AC_AF_IPV4: return 32;
    case AC_AF_IPV6: return 128;
    case AC_AF_POOL: return 256;
    default: return 0;
    }
}

static int prefix_match(const ac_address_t *prefix,
                        const ac_address_t *addr)
{
    uint16_t max_bits;
    uint8_t full_bytes, rem_bits;
    uint8_t i;

    if (prefix->family != addr->family)
        return 0;

    max_bits = addr_max_bits(prefix->family);
    if (max_bits == 0)
        return 0;

    if (prefix->prefix_len > max_bits)
        return 0;

    if (prefix->prefix_len == 0)
        return 1;

    full_bytes = prefix->prefix_len / 8;
    rem_bits = prefix->prefix_len % 8;

    for (i = 0; i < full_bytes; i++) {
        if (prefix->addr[i] != addr->addr[i])
            return 0;
    }

    if (rem_bits > 0) {
        uint8_t mask = (uint8_t)(0xFFu << (8u - rem_bits));
        if ((prefix->addr[full_bytes] & mask) !=
            (addr->addr[full_bytes] & mask))
            return 0;
    }

    return 1;
}

static int prefixes_overlap(const ac_address_t *a, const ac_address_t *b)
{
    if (a->family != b->family)
        return 0;

    return prefix_match(a, b) || prefix_match(b, a);
}

/* Build member composite key: pubkey + subnet_id */
static void make_member_key(uint8_t out[AC_MEMBER_KEY_LEN],
                            const uint8_t pubkey[AC_PUBKEY_LEN],
                            const uint8_t subnet_id[AC_SUBNET_ID_LEN])
{
    memcpy(out, pubkey, AC_PUBKEY_LEN);
    memcpy(out + AC_PUBKEY_LEN, subnet_id, AC_SUBNET_ID_LEN);
}

/* Find subnet by id (caller holds lock). */
static ac_subnet_record_t *find_subnet(ac_subnet_store_t *ss,
                                        const uint8_t subnet_id[AC_SUBNET_ID_LEN])
{
    return (ac_subnet_record_t *)ac_hashmap_get(&ss->subnet_map,
                                                 subnet_id, AC_SUBNET_ID_LEN);
}

/* Validate a SUBNET_CREATE transaction (caller holds lock). */
static int validate_subnet_create(ac_subnet_store_t *ss,
                                  const ac_tx_subnet_create_t *sc,
                                  const uint8_t *creator)
{
    ac_hashmap_iter_t it;
    const void *k;
    uint32_t kl;
    void *v;
    uint16_t max_bits;

    (void)creator;

    if (id_len(sc->subnet_id, AC_SUBNET_ID_LEN) == 0) {
        ac_log(AC_LOG_WARN, "validate: empty subnet_id");
        return AC_ERR_INVAL;
    }

    max_bits = addr_max_bits(sc->prefix.family);
    if (max_bits == 0) {
        ac_log(AC_LOG_WARN, "validate: invalid prefix family");
        return AC_ERR_INVAL;
    }

    if (sc->prefix.prefix_len > max_bits) {
        ac_log(AC_LOG_WARN, "validate: prefix_len exceeds max for family");
        return AC_ERR_INVAL;
    }

    /* Gateway REQUIRED unless NO_GATEWAY flag (N14 hardened) */
    if (!(sc->flags & AC_SUBNET_FLAG_NO_GATEWAY)) {
        ac_address_t zero;
        memset(&zero, 0, sizeof(zero));
        if (memcmp(&sc->gateway, &zero, sizeof(zero)) == 0) {
            ac_log(AC_LOG_WARN, "validate: gateway REQUIRED (use --no-gateway for explicit opt-out)");
            return AC_ERR_INVAL;
        }
        if (!prefix_match(&sc->prefix, &sc->gateway)) {
            ac_log(AC_LOG_WARN, "validate: gateway not within subnet prefix");
            return AC_ERR_INVAL;
        }
    }

    /* DNS REQUIRED unless NO_DNS flag (N15 hardened) */
    if (!(sc->flags & AC_SUBNET_FLAG_NO_DNS)) {
        if (sc->dns_count == 0) {
            ac_log(AC_LOG_WARN, "validate: dns REQUIRED (use --no-dns for explicit opt-out)");
            return AC_ERR_INVAL;
        }
        if (sc->dns_count > AC_MAX_DNS_ADDRS) {
            ac_log(AC_LOG_WARN, "validate: too many DNS servers");
            return AC_ERR_INVAL;
        }
    }

    /* Check for duplicate subnet_id */
    {
        ac_subnet_record_t *existing = find_subnet(ss, sc->subnet_id);
        if (existing && existing->active) {
            ac_log(AC_LOG_WARN, "validate: subnet_id already exists");
            return AC_ERR_EXIST;
        }
    }

    /* Check for overlapping prefix (N11) via hashmap iteration */
    ac_hashmap_iter_init(&it, &ss->subnet_map);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v)) {
        ac_subnet_record_t *rec = (ac_subnet_record_t *)v;
        if (rec->active && prefixes_overlap(&rec->prefix, &sc->prefix)) {
            ac_log(AC_LOG_WARN, "validate: prefix overlaps existing subnet");
            return AC_ERR_OVERLAP;
        }
    }

    /* Capacity check */
    if (ss->max_subnets > 0 && ss->subnet_count >= ss->max_subnets) {
        ac_log(AC_LOG_WARN, "validate: subnet store full (%u/%u)",
               ss->subnet_count, ss->max_subnets);
        return AC_ERR_NOMEM;
    }

    return AC_OK;
}

/* Validate a SUBNET_ASSIGN transaction (caller holds lock). */
static int validate_subnet_assign(ac_subnet_store_t *ss,
                                  const ac_tx_subnet_assign_t *sa)
{
    ac_subnet_record_t *subnet;
    uint8_t mkey[AC_MEMBER_KEY_LEN];

    subnet = find_subnet(ss, sa->subnet_id);
    if (!subnet || !subnet->active) {
        ac_log(AC_LOG_WARN, "validate: subnet_id not found for ASSIGN");
        return AC_ERR_NOENT;
    }

    /* Check if node already assigned to this subnet */
    make_member_key(mkey, sa->node_pubkey, sa->subnet_id);
    if (ac_hashmap_get(&ss->member_map, mkey, AC_MEMBER_KEY_LEN) != NULL) {
        ac_log(AC_LOG_WARN, "validate: node already assigned to subnet");
        return AC_ERR_EXIST;
    }

    /* Capacity check */
    if (ss->max_members > 0 && ss->member_count >= ss->max_members) {
        ac_log(AC_LOG_WARN, "validate: member table full (%u/%u)",
               ss->member_count, ss->max_members);
        return AC_ERR_NOMEM;
    }

    return AC_OK;
}

/* Apply a SUBNET_CREATE (caller holds lock). */
static int apply_subnet_create(ac_subnet_store_t *ss,
                                const ac_tx_subnet_create_t *sc,
                                const uint8_t *creator,
                                uint32_t block_index)
{
    ac_subnet_record_t *rec;

    rec = (ac_subnet_record_t *)ac_zalloc(sizeof(*rec), AC_MEM_NORMAL);
    if (!rec)
        return AC_ERR_NOMEM;

    memcpy(rec->subnet_id, sc->subnet_id, AC_SUBNET_ID_LEN);
    rec->prefix = sc->prefix;
    rec->gateway = sc->gateway;
    memcpy(rec->dns, sc->dns, sizeof(sc->dns));
    rec->dns_count = sc->dns_count;
    rec->vlan_id = sc->vlan_id;
    rec->flags = sc->flags;
    memcpy(rec->creator, creator, AC_PUBKEY_LEN);
    rec->created_block = block_index;
    rec->active = 1;

    if (ac_hashmap_put(&ss->subnet_map, sc->subnet_id, AC_SUBNET_ID_LEN,
                       rec, NULL) != AC_OK) {
        ac_free(rec);
        return AC_ERR_NOMEM;
    }
    ss->subnet_count++;
    ac_log(AC_LOG_INFO, "subnet created: %.31s", sc->subnet_id);
    return AC_OK;
}

/* Apply a SUBNET_ASSIGN (caller holds lock). */
static int apply_subnet_assign(ac_subnet_store_t *ss,
                                const ac_tx_subnet_assign_t *sa,
                                uint32_t block_index)
{
    ac_subnet_member_t *mem;
    uint8_t mkey[AC_MEMBER_KEY_LEN];

    mem = (ac_subnet_member_t *)ac_zalloc(sizeof(*mem), AC_MEM_NORMAL);
    if (!mem)
        return AC_ERR_NOMEM;

    memcpy(mem->node_pubkey, sa->node_pubkey, AC_PUBKEY_LEN);
    memcpy(mem->subnet_id, sa->subnet_id, AC_SUBNET_ID_LEN);
    mem->assigned_block = block_index;

    make_member_key(mkey, sa->node_pubkey, sa->subnet_id);
    if (ac_hashmap_put(&ss->member_map, mkey, AC_MEMBER_KEY_LEN,
                       mem, NULL) != AC_OK) {
        ac_free(mem);
        return AC_ERR_NOMEM;
    }
    ss->member_count++;
    ac_log(AC_LOG_INFO, "node assigned to subnet: %.31s", sa->subnet_id);
    return AC_OK;
}

/* ================================================================== */
/*  Public API                                                         */
/* ================================================================== */

int ac_subnet_init(ac_subnet_store_t *ss,
                   uint32_t max_subnets, uint32_t max_members)
{
    int rc;

    if (!ss)
        return AC_ERR_INVAL;

    memset(ss, 0, sizeof(*ss));

    rc = ac_mutex_init(&ss->lock);
    if (rc != AC_OK)
        return rc;

    ss->max_subnets = max_subnets;
    ss->max_members = max_members;

    /* S15: validate vmalloc size */
    if (max_subnets > 0) {
        size_t overhead = sizeof(ac_subnet_record_t) + AC_SUBNET_ID_LEN + 64;
        if ((uint64_t)max_subnets * overhead > (uint64_t)1 << 31) {
            ac_log(AC_LOG_ERROR, "max_subnets %u would exceed vmalloc limit",
                   max_subnets);
            ac_mutex_destroy(&ss->lock);
            return AC_ERR_NOMEM;
        }
    }

    rc = ac_hashmap_init(&ss->subnet_map, 32, max_subnets);
    if (rc != AC_OK) {
        ac_mutex_destroy(&ss->lock);
        return rc;
    }

    rc = ac_hashmap_init(&ss->member_map, 64, max_members);
    if (rc != AC_OK) {
        ac_hashmap_destroy(&ss->subnet_map);
        ac_mutex_destroy(&ss->lock);
        return rc;
    }

    ac_log(AC_LOG_INFO, "subnet store initialized (max_subnets=%u, max_members=%u)",
           max_subnets, max_members);
    return AC_OK;
}

void ac_subnet_destroy(ac_subnet_store_t *ss)
{
    ac_hashmap_iter_t it;
    const void *k;
    uint32_t kl;
    void *v;

    if (!ss)
        return;

    ac_mutex_lock(&ss->lock);

    ac_hashmap_iter_init(&it, &ss->subnet_map);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v))
        ac_free(v);
    ac_hashmap_destroy(&ss->subnet_map);

    ac_hashmap_iter_init(&it, &ss->member_map);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v))
        ac_free(v);
    ac_hashmap_destroy(&ss->member_map);

    ss->subnet_count = 0;
    ss->member_count = 0;
    ac_mutex_unlock(&ss->lock);

    ac_mutex_destroy(&ss->lock);
    ac_log(AC_LOG_INFO, "subnet store destroyed");
}

int ac_subnet_validate_block(ac_subnet_store_t *ss,
                             const ac_block_t *blk)
{
    uint16_t i;
    int rc;

    if (!ss || !blk)
        return AC_ERR_INVAL;

    ac_mutex_lock(&ss->lock);

    for (i = 0; i < blk->tx_count; i++) {
        const ac_transaction_t *tx = &blk->txs[i];

        switch (tx->type) {
        case AC_TX_SUBNET_CREATE:
            rc = validate_subnet_create(ss, &tx->payload.subnet_create,
                                        tx->node_pubkey);
            if (rc != AC_OK) {
                ac_mutex_unlock(&ss->lock);
                return rc;
            }
            break;

        case AC_TX_SUBNET_ASSIGN:
            rc = validate_subnet_assign(ss, &tx->payload.subnet_assign);
            if (rc != AC_OK) {
                ac_mutex_unlock(&ss->lock);
                return rc;
            }
            break;

        default:
            break;
        }
    }

    ac_mutex_unlock(&ss->lock);
    return AC_OK;
}

int ac_subnet_apply_block(ac_subnet_store_t *ss,
                          const ac_block_t *blk)
{
    uint16_t i;
    int rc;

    if (!ss || !blk)
        return AC_ERR_INVAL;

    ac_mutex_lock(&ss->lock);

    for (i = 0; i < blk->tx_count; i++) {
        const ac_transaction_t *tx = &blk->txs[i];

        switch (tx->type) {
        case AC_TX_SUBNET_CREATE:
            rc = apply_subnet_create(ss, &tx->payload.subnet_create,
                                     tx->node_pubkey, blk->index);
            if (rc != AC_OK) {
                ac_log(AC_LOG_WARN, "apply: subnet create failed: %d", rc);
            }
            break;

        case AC_TX_SUBNET_ASSIGN:
            rc = apply_subnet_assign(ss, &tx->payload.subnet_assign,
                                     blk->index);
            if (rc != AC_OK) {
                ac_log(AC_LOG_WARN, "apply: subnet assign failed: %d", rc);
            }
            break;

        default:
            break;
        }
    }

    ac_mutex_unlock(&ss->lock);
    return AC_OK;
}

const ac_subnet_record_t *ac_subnet_find(const ac_subnet_store_t *ss,
                                         const uint8_t subnet_id[AC_SUBNET_ID_LEN])
{
    ac_subnet_record_t *rec;
    if (!ss || !subnet_id)
        return NULL;

    rec = (ac_subnet_record_t *)ac_hashmap_get(
        (ac_hashmap_t *)&ss->subnet_map, subnet_id, AC_SUBNET_ID_LEN);
    if (rec && rec->active)
        return rec;
    return NULL;
}

int ac_subnet_contains(const ac_subnet_record_t *subnet,
                       const ac_address_t *addr)
{
    if (!subnet || !addr)
        return 0;
    return prefix_match(&subnet->prefix, addr);
}

int ac_subnet_overlaps(const ac_address_t *a, const ac_address_t *b)
{
    if (!a || !b)
        return 0;
    return prefixes_overlap(a, b);
}

int ac_subnet_is_member(const ac_subnet_store_t *ss,
                        const uint8_t node_pubkey[AC_PUBKEY_LEN],
                        const uint8_t subnet_id[AC_SUBNET_ID_LEN])
{
    uint8_t mkey[AC_MEMBER_KEY_LEN];
    if (!ss || !node_pubkey || !subnet_id)
        return 0;

    make_member_key(mkey, node_pubkey, subnet_id);
    return ac_hashmap_get((ac_hashmap_t *)&ss->member_map,
                          mkey, AC_MEMBER_KEY_LEN) != NULL;
}

uint32_t ac_subnet_count(const ac_subnet_store_t *ss)
{
    if (!ss)
        return 0;
    return ss->subnet_count;
}

uint32_t ac_subnet_member_count(const ac_subnet_store_t *ss)
{
    if (!ss)
        return 0;
    return ss->member_count;
}

int ac_subnet_rebuild(ac_subnet_store_t *ss,
                      const ac_block_t *blocks,
                      uint32_t block_count)
{
    ac_hashmap_iter_t it;
    const void *k;
    uint32_t kl;
    void *v;
    uint32_t i;

    if (!ss || (!blocks && block_count > 0))
        return AC_ERR_INVAL;

    ac_mutex_lock(&ss->lock);

    /* Free existing entries */
    ac_hashmap_iter_init(&it, &ss->subnet_map);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v)) {
        ac_free(v);
        ac_hashmap_iter_remove(&it);
    }
    ss->subnet_count = 0;

    ac_hashmap_iter_init(&it, &ss->member_map);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v)) {
        ac_free(v);
        ac_hashmap_iter_remove(&it);
    }
    ss->member_count = 0;

    /* Replay blocks */
    for (i = 0; i < block_count; i++) {
        uint16_t j;
        const ac_block_t *blk = &blocks[i];

        for (j = 0; j < blk->tx_count; j++) {
            const ac_transaction_t *tx = &blk->txs[j];

            switch (tx->type) {
            case AC_TX_SUBNET_CREATE:
                apply_subnet_create(ss, &tx->payload.subnet_create,
                                    tx->node_pubkey, blk->index);
                break;

            case AC_TX_SUBNET_ASSIGN:
                apply_subnet_assign(ss, &tx->payload.subnet_assign,
                                    blk->index);
                break;

            default:
                break;
            }
        }
    }

    ac_mutex_unlock(&ss->lock);
    ac_log(AC_LOG_INFO, "subnet store rebuilt: %u subnets, %u members",
           ss->subnet_count, ss->member_count);
    return AC_OK;
}
