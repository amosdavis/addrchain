/*
 * ac_subnet.c — Subnet management implementation
 *
 * Manages SUBNET_CREATE / SUBNET_ASSIGN transactions. Validates prefix
 * membership, detects overlapping subnets, enforces gateway/DNS requirements,
 * and tracks node-to-subnet assignments.
 *
 * Mitigates: N02,N05,N11,N12,N13,N14,N15,N20,N29,N31
 */

#include "ac_subnet.h"
#include "ac_chain.h"
#include "ac_crypto.h"

#include <string.h>

/* ================================================================== */
/*  Internal helpers                                                   */
/* ================================================================== */

/* Safe strlen for fixed-size ID fields */
static uint32_t id_len(const uint8_t *id, uint32_t max)
{
    uint32_t i;
    for (i = 0; i < max; i++) {
        if (id[i] == 0)
            return i;
    }
    return max;
}

/* Compare two subnet IDs */
static int id_eq(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, AC_SUBNET_ID_LEN) == 0;
}

/*
 * addr_effective_bits — Return the number of meaningful bits for a family.
 */
static uint16_t addr_max_bits(uint8_t family)
{
    switch (family) {
    case AC_AF_IPV4: return 32;
    case AC_AF_IPV6: return 128;
    case AC_AF_POOL: return 256;
    default: return 0;
    }
}

/*
 * prefix_match — Check if addr is within prefix/prefix_len.
 * Both must have the same family.
 */
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
        return 1; /* /0 matches everything */

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

/*
 * prefixes_overlap — Two CIDR prefixes overlap if either contains the
 * network address of the other.
 */
static int prefixes_overlap(const ac_address_t *a, const ac_address_t *b)
{
    if (a->family != b->family)
        return 0;

    /* If A's prefix contains B's network addr, or vice versa */
    return prefix_match(a, b) || prefix_match(b, a);
}

/* Validate a SUBNET_CREATE transaction */
static int validate_subnet_create(const ac_subnet_store_t *ss,
                                  const ac_tx_subnet_create_t *sc,
                                  const uint8_t *creator)
{
    uint32_t i;
    uint16_t max_bits;

    (void)creator;

    /* Subnet ID must not be empty */
    if (id_len(sc->subnet_id, AC_SUBNET_ID_LEN) == 0) {
        ac_log(AC_LOG_WARN, "validate: empty subnet_id");
        return AC_ERR_INVAL;
    }

    /* Prefix must have valid family */
    max_bits = addr_max_bits(sc->prefix.family);
    if (max_bits == 0) {
        ac_log(AC_LOG_WARN, "validate: invalid prefix family");
        return AC_ERR_INVAL;
    }

    /* Prefix length must not exceed address size */
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
        /* Gateway must be within the subnet prefix */
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
    for (i = 0; i < ss->subnet_count; i++) {
        if (ss->subnets[i].active &&
            id_eq(ss->subnets[i].subnet_id, sc->subnet_id)) {
            ac_log(AC_LOG_WARN, "validate: subnet_id already exists");
            return AC_ERR_EXIST;
        }
    }

    /* Check for overlapping prefix (N11) */
    for (i = 0; i < ss->subnet_count; i++) {
        if (ss->subnets[i].active &&
            prefixes_overlap(&ss->subnets[i].prefix, &sc->prefix)) {
            ac_log(AC_LOG_WARN, "validate: prefix overlaps existing subnet");
            return AC_ERR_OVERLAP;
        }
    }

    /* Capacity check */
    if (ss->subnet_count >= AC_MAX_SUBNETS) {
        ac_log(AC_LOG_WARN, "validate: subnet store full");
        return AC_ERR_NOMEM;
    }

    return AC_OK;
}

/* Validate a SUBNET_ASSIGN transaction */
static int validate_subnet_assign(const ac_subnet_store_t *ss,
                                  const ac_tx_subnet_assign_t *sa)
{
    uint32_t i;
    int found = 0;

    /* Target subnet must exist */
    for (i = 0; i < ss->subnet_count; i++) {
        if (ss->subnets[i].active &&
            id_eq(ss->subnets[i].subnet_id, sa->subnet_id)) {
            found = 1;
            break;
        }
    }
    if (!found) {
        ac_log(AC_LOG_WARN, "validate: subnet_id not found for ASSIGN");
        return AC_ERR_NOENT;
    }

    /* Check if node already assigned to this subnet */
    for (i = 0; i < ss->member_count; i++) {
        if (memcmp(ss->members[i].node_pubkey, sa->node_pubkey, AC_PUBKEY_LEN) == 0 &&
            id_eq(ss->members[i].subnet_id, sa->subnet_id)) {
            ac_log(AC_LOG_WARN, "validate: node already assigned to subnet");
            return AC_ERR_EXIST;
        }
    }

    /* Capacity check */
    if (ss->member_count >= AC_MAX_SUBNET_MEMBERS) {
        ac_log(AC_LOG_WARN, "validate: member table full");
        return AC_ERR_NOMEM;
    }

    return AC_OK;
}

/* Apply a SUBNET_CREATE */
static void apply_subnet_create(ac_subnet_store_t *ss,
                                const ac_tx_subnet_create_t *sc,
                                const uint8_t *creator,
                                uint32_t block_index)
{
    ac_subnet_record_t *rec = &ss->subnets[ss->subnet_count];

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

    ss->subnet_count++;
    ac_log(AC_LOG_INFO, "subnet created: %.31s", sc->subnet_id);
}

/* Apply a SUBNET_ASSIGN */
static void apply_subnet_assign(ac_subnet_store_t *ss,
                                const ac_tx_subnet_assign_t *sa,
                                uint32_t block_index)
{
    ac_subnet_member_t *mem = &ss->members[ss->member_count];

    memcpy(mem->node_pubkey, sa->node_pubkey, AC_PUBKEY_LEN);
    memcpy(mem->subnet_id, sa->subnet_id, AC_SUBNET_ID_LEN);
    mem->assigned_block = block_index;

    ss->member_count++;
    ac_log(AC_LOG_INFO, "node assigned to subnet: %.31s", sa->subnet_id);
}

/* ================================================================== */
/*  Public API                                                         */
/* ================================================================== */

int ac_subnet_init(ac_subnet_store_t *ss)
{
    if (!ss)
        return AC_ERR_INVAL;

    memset(ss, 0, sizeof(*ss));
    ac_mutex_init(&ss->lock);
    ac_log(AC_LOG_INFO, "subnet store initialized");
    return AC_OK;
}

void ac_subnet_destroy(ac_subnet_store_t *ss)
{
    if (!ss)
        return;
    ac_mutex_destroy(&ss->lock);
    memset(ss, 0, sizeof(*ss));
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
            /* Non-subnet tx types are fine — skip */
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

    if (!ss || !blk)
        return AC_ERR_INVAL;

    ac_mutex_lock(&ss->lock);

    for (i = 0; i < blk->tx_count; i++) {
        const ac_transaction_t *tx = &blk->txs[i];

        switch (tx->type) {
        case AC_TX_SUBNET_CREATE:
            if (ss->subnet_count < AC_MAX_SUBNETS)
                apply_subnet_create(ss, &tx->payload.subnet_create,
                                    tx->node_pubkey, blk->index);
            break;

        case AC_TX_SUBNET_ASSIGN:
            if (ss->member_count < AC_MAX_SUBNET_MEMBERS)
                apply_subnet_assign(ss, &tx->payload.subnet_assign,
                                    blk->index);
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
    uint32_t i;
    if (!ss || !subnet_id)
        return NULL;

    for (i = 0; i < ss->subnet_count; i++) {
        if (ss->subnets[i].active &&
            id_eq(ss->subnets[i].subnet_id, subnet_id))
            return &ss->subnets[i];
    }
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
    uint32_t i;
    if (!ss || !node_pubkey || !subnet_id)
        return 0;

    for (i = 0; i < ss->member_count; i++) {
        if (memcmp(ss->members[i].node_pubkey, node_pubkey, AC_PUBKEY_LEN) == 0 &&
            id_eq(ss->members[i].subnet_id, subnet_id))
            return 1;
    }
    return 0;
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
    uint32_t i;

    if (!ss || (!blocks && block_count > 0))
        return AC_ERR_INVAL;

    ac_mutex_lock(&ss->lock);

    /* Reset state */
    ss->subnet_count = 0;
    ss->member_count = 0;
    memset(ss->subnets, 0, sizeof(ss->subnets));
    memset(ss->members, 0, sizeof(ss->members));

    for (i = 0; i < block_count; i++) {
        uint16_t j;
        const ac_block_t *blk = &blocks[i];

        for (j = 0; j < blk->tx_count; j++) {
            const ac_transaction_t *tx = &blk->txs[j];

            switch (tx->type) {
            case AC_TX_SUBNET_CREATE:
                if (ss->subnet_count < AC_MAX_SUBNETS)
                    apply_subnet_create(ss, &tx->payload.subnet_create,
                                        tx->node_pubkey, blk->index);
                break;

            case AC_TX_SUBNET_ASSIGN:
                if (ss->member_count < AC_MAX_SUBNET_MEMBERS)
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
