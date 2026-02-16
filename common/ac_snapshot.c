/*
 * ac_snapshot.c — State snapshot serialization and verification
 *
 * Two-pass serialization: first pass computes total size, second pass
 * writes data.  Each section is a count (u32) followed by flat records.
 * SHA-256 computed over everything after the 44-byte header.
 *
 * V1 note (S22): hashmap iteration order is instance-dependent so
 * snapshot hashes are node-local.  Cross-node comparison uses the
 * on-chain SNAPSHOT tx hash, not raw snapshot comparison.
 *
 * Mitigates: S06,S07,S08,S22,S24,K01,K02,K03,K06
 */

#include "ac_snapshot.h"
#include "ac_crypto.h"
#include "ac_hashmap.h"

#include <string.h>

/* Header size must be exactly 48 bytes (4+4+4+32+4) */
AC_STATIC_ASSERT(sizeof(ac_snapshot_header_t) == 48,
                 "snapshot header must be 48 bytes");

/* ================================================================== */
/*  Write helpers                                                      */
/* ================================================================== */

/* Write a little-endian uint32 at *pos, advance *pos. */
static void write_u32(uint8_t *buf, uint32_t *pos, uint32_t val)
{
    uint32_t le = ac_cpu_to_le32(val);
    memcpy(buf + *pos, &le, 4);
    *pos += 4;
}

/* Write a little-endian uint16 at *pos, advance *pos. */
static void write_u16(uint8_t *buf, uint32_t *pos, uint16_t val)
{
    uint16_t le = ac_cpu_to_le16(val);
    memcpy(buf + *pos, &le, 2);
    *pos += 2;
}

/* Write raw bytes at *pos, advance *pos. */
static void write_bytes(uint8_t *buf, uint32_t *pos,
                        const void *src, uint32_t len)
{
    memcpy(buf + *pos, src, len);
    *pos += len;
}

/* Write a single byte at *pos, advance *pos. */
static void write_u8(uint8_t *buf, uint32_t *pos, uint8_t val)
{
    buf[*pos] = val;
    *pos += 1;
}

/* ================================================================== */
/*  Read helpers                                                       */
/* ================================================================== */

static int read_u32(const uint8_t *buf, uint32_t size,
                    uint32_t *pos, uint32_t *out)
{
    if (*pos + 4 > size) return AC_ERR_INVAL;
    uint32_t le;
    memcpy(&le, buf + *pos, 4);
    *out = ac_le32_to_cpu(le);
    *pos += 4;
    return AC_OK;
}

static int read_u16(const uint8_t *buf, uint32_t size,
                    uint32_t *pos, uint16_t *out)
{
    if (*pos + 2 > size) return AC_ERR_INVAL;
    uint16_t le;
    memcpy(&le, buf + *pos, 2);
    *out = ac_le16_to_cpu(le);
    *pos += 2;
    return AC_OK;
}

static int read_u8(const uint8_t *buf, uint32_t size,
                   uint32_t *pos, uint8_t *out)
{
    if (*pos + 1 > size) return AC_ERR_INVAL;
    *out = buf[*pos];
    *pos += 1;
    return AC_OK;
}

static int read_bytes(const uint8_t *buf, uint32_t size,
                      uint32_t *pos, void *out, uint32_t len)
{
    if (*pos + len > size) return AC_ERR_INVAL;
    memcpy(out, buf + *pos, len);
    *pos += len;
    return AC_OK;
}

/* ================================================================== */
/*  Size computation (pass 1)                                          */
/* ================================================================== */

static uint32_t section_claims_size(ac_claim_store_t *cs)
{
    /* count(4) + N * sizeof(ac_claim_record_t) */
    return 4 + ac_hashmap_count(&cs->claims_map) *
               (uint32_t)sizeof(ac_claim_record_t);
}

static uint32_t section_subnets_size(ac_subnet_store_t *ss)
{
    return 4 + ac_hashmap_count(&ss->subnet_map) *
               (uint32_t)sizeof(ac_subnet_record_t);
}

static uint32_t section_members_size(ac_subnet_store_t *ss)
{
    return 4 + ac_hashmap_count(&ss->member_map) *
               (uint32_t)sizeof(ac_subnet_member_t);
}

static uint32_t section_vpn_size(ac_vpn_store_t *vs)
{
    return 4 + ac_hashmap_count(&vs->tunnel_map) *
               (uint32_t)sizeof(ac_vpn_tunnel_t);
}

static uint32_t section_partitions_size(ac_partition_store_t *ps)
{
    /*
     * Per partition: partition_id(32) + vlan(2) + active(1)
     *              + subnet_count(4) + subnet_count * subnet_id(32)
     */
    uint32_t total = 4; /* count */
    ac_hashmap_iter_t it;
    const void *key;
    uint32_t key_len;
    void *value;

    ac_hashmap_iter_init(&it, &ps->partition_map);
    while (ac_hashmap_iter_next(&it, &key, &key_len, &value)) {
        ac_partition_record_t *pr = (ac_partition_record_t *)value;
        total += AC_PARTITION_ID_LEN + 2 + 1 + 4 +
                 pr->subnet_count * AC_SUBNET_ID_LEN;
    }
    return total;
}

static uint32_t section_cross_rules_size(ac_partition_store_t *ps)
{
    return 4 + ac_hashmap_count(&ps->cross_rule_map) *
               (uint32_t)sizeof(ac_cross_rule_t);
}

static uint32_t section_seq_size(ac_chain_t *chain)
{
    return 4 + ac_hashmap_count(&chain->seq_map) *
               (uint32_t)sizeof(ac_seq_entry_t);
}

static uint32_t section_dag_edges_size(ac_dag_t *dag)
{
    /* count(4) + N * (parent_key(33) + child_key(33)) */
    uint32_t edge_count = 0;
    ac_hashmap_iter_t node_it;
    const void *nk;
    uint32_t nkl;
    void *nv;

    ac_hashmap_iter_init(&node_it, &dag->nodes);
    while (ac_hashmap_iter_next(&node_it, &nk, &nkl, &nv)) {
        ac_dag_node_t *node = (ac_dag_node_t *)nv;
        edge_count += ac_hashmap_count(&node->children);
    }
    return 4 + edge_count * (AC_DAG_KEY_LEN * 2);
}

/* ================================================================== */
/*  Serialize sections (pass 2)                                        */
/* ================================================================== */

static void serialize_claims(uint8_t *buf, uint32_t *pos,
                             ac_claim_store_t *cs)
{
    ac_hashmap_iter_t it;
    const void *key;
    uint32_t key_len;
    void *value;
    uint32_t count = ac_hashmap_count(&cs->claims_map);

    write_u32(buf, pos, count);
    ac_hashmap_iter_init(&it, &cs->claims_map);
    while (ac_hashmap_iter_next(&it, &key, &key_len, &value)) {
        ac_claim_record_t *cr = (ac_claim_record_t *)value;
        write_bytes(buf, pos, cr, (uint32_t)sizeof(ac_claim_record_t));
    }
}

static void serialize_subnets(uint8_t *buf, uint32_t *pos,
                              ac_subnet_store_t *ss)
{
    ac_hashmap_iter_t it;
    const void *key;
    uint32_t key_len;
    void *value;
    uint32_t count = ac_hashmap_count(&ss->subnet_map);

    write_u32(buf, pos, count);
    ac_hashmap_iter_init(&it, &ss->subnet_map);
    while (ac_hashmap_iter_next(&it, &key, &key_len, &value)) {
        ac_subnet_record_t *sr = (ac_subnet_record_t *)value;
        write_bytes(buf, pos, sr, (uint32_t)sizeof(ac_subnet_record_t));
    }
}

static void serialize_members(uint8_t *buf, uint32_t *pos,
                              ac_subnet_store_t *ss)
{
    ac_hashmap_iter_t it;
    const void *key;
    uint32_t key_len;
    void *value;
    uint32_t count = ac_hashmap_count(&ss->member_map);

    write_u32(buf, pos, count);
    ac_hashmap_iter_init(&it, &ss->member_map);
    while (ac_hashmap_iter_next(&it, &key, &key_len, &value)) {
        ac_subnet_member_t *sm = (ac_subnet_member_t *)value;
        write_bytes(buf, pos, sm, (uint32_t)sizeof(ac_subnet_member_t));
    }
}

static void serialize_vpn(uint8_t *buf, uint32_t *pos,
                          ac_vpn_store_t *vs)
{
    ac_hashmap_iter_t it;
    const void *key;
    uint32_t key_len;
    void *value;
    uint32_t count = ac_hashmap_count(&vs->tunnel_map);

    write_u32(buf, pos, count);
    ac_hashmap_iter_init(&it, &vs->tunnel_map);
    while (ac_hashmap_iter_next(&it, &key, &key_len, &value)) {
        ac_vpn_tunnel_t *vt = (ac_vpn_tunnel_t *)value;
        write_bytes(buf, pos, vt, (uint32_t)sizeof(ac_vpn_tunnel_t));
    }
}

static void serialize_partitions(uint8_t *buf, uint32_t *pos,
                                 ac_partition_store_t *ps)
{
    ac_hashmap_iter_t it;
    const void *key;
    uint32_t key_len;
    void *value;
    uint32_t count = ac_hashmap_count(&ps->partition_map);
    uint32_t i;

    write_u32(buf, pos, count);
    ac_hashmap_iter_init(&it, &ps->partition_map);
    while (ac_hashmap_iter_next(&it, &key, &key_len, &value)) {
        ac_partition_record_t *pr = (ac_partition_record_t *)value;
        write_bytes(buf, pos, pr->partition_id, AC_PARTITION_ID_LEN);
        write_u16(buf, pos, pr->vlan_id);
        write_u8(buf, pos, pr->active);
        write_u32(buf, pos, pr->subnet_count);
        for (i = 0; i < pr->subnet_count; i++) {
            write_bytes(buf, pos, pr->subnet_ids[i], AC_SUBNET_ID_LEN);
        }
    }
}

static void serialize_cross_rules(uint8_t *buf, uint32_t *pos,
                                  ac_partition_store_t *ps)
{
    ac_hashmap_iter_t it;
    const void *key;
    uint32_t key_len;
    void *value;
    uint32_t count = ac_hashmap_count(&ps->cross_rule_map);

    write_u32(buf, pos, count);
    ac_hashmap_iter_init(&it, &ps->cross_rule_map);
    while (ac_hashmap_iter_next(&it, &key, &key_len, &value)) {
        ac_cross_rule_t *cr = (ac_cross_rule_t *)value;
        write_bytes(buf, pos, cr, (uint32_t)sizeof(ac_cross_rule_t));
    }
}

static void serialize_seq_table(uint8_t *buf, uint32_t *pos,
                                ac_chain_t *chain)
{
    ac_hashmap_iter_t it;
    const void *key;
    uint32_t key_len;
    void *value;
    uint32_t count = ac_hashmap_count(&chain->seq_map);

    write_u32(buf, pos, count);
    ac_hashmap_iter_init(&it, &chain->seq_map);
    while (ac_hashmap_iter_next(&it, &key, &key_len, &value)) {
        ac_seq_entry_t *se = (ac_seq_entry_t *)value;
        write_bytes(buf, pos, se, (uint32_t)sizeof(ac_seq_entry_t));
    }
}

static void serialize_dag_edges(uint8_t *buf, uint32_t *pos,
                                ac_dag_t *dag)
{
    ac_hashmap_iter_t node_it, child_it;
    const void *nk, *ck;
    uint32_t nkl, ckl;
    void *nv, *cv;
    uint32_t edge_count = 0;
    uint32_t count_pos;

    /* Reserve space for edge count, fill in later */
    count_pos = *pos;
    *pos += 4;

    ac_hashmap_iter_init(&node_it, &dag->nodes);
    while (ac_hashmap_iter_next(&node_it, &nk, &nkl, &nv)) {
        ac_dag_node_t *node = (ac_dag_node_t *)nv;
        /* Parent key is the node's own key (type+id = 33 bytes) */
        ac_hashmap_iter_init(&child_it, &node->children);
        while (ac_hashmap_iter_next(&child_it, &ck, &ckl, &cv)) {
            /* parent_key(33) + child_key(33) */
            write_bytes(buf, pos, nk, AC_DAG_KEY_LEN);
            write_bytes(buf, pos, ck, AC_DAG_KEY_LEN);
            edge_count++;
        }
    }

    /* Patch edge count */
    {
        uint32_t le = ac_cpu_to_le32(edge_count);
        memcpy(buf + count_pos, &le, 4);
    }
}

/* ================================================================== */
/*  Public API                                                         */
/* ================================================================== */

int ac_snapshot_create(ac_snapshot_t *snap,
                       uint32_t block_index,
                       ac_chain_t *chain,
                       ac_claim_store_t *cs,
                       ac_subnet_store_t *ss,
                       ac_vpn_store_t *vs,
                       ac_partition_store_t *ps,
                       ac_dag_t *dag)
{
    uint32_t total_size, pos;
    uint8_t *buf;
    ac_snapshot_header_t hdr;

    if (!snap || !chain || !cs || !ss || !vs || !ps || !dag)
        return AC_ERR_INVAL;

    memset(snap, 0, sizeof(*snap));

    /* Pass 1: compute total size */
    total_size = (uint32_t)sizeof(ac_snapshot_header_t);

    ac_mutex_lock(&chain->lock);
    ac_mutex_lock(&cs->lock);
    ac_mutex_lock(&ss->lock);
    ac_mutex_lock(&ps->lock);
    ac_mutex_lock(&vs->lock);
    ac_mutex_lock(&dag->lock);

    total_size += section_claims_size(cs);
    total_size += section_subnets_size(ss);
    total_size += section_members_size(ss);
    total_size += section_vpn_size(vs);
    total_size += section_partitions_size(ps);
    total_size += section_cross_rules_size(ps);
    total_size += section_seq_size(chain);
    total_size += section_dag_edges_size(dag);

    /* Allocate buffer */
    buf = (uint8_t *)ac_zalloc(total_size, AC_MEM_NORMAL);
    if (!buf) {
        ac_mutex_unlock(&dag->lock);
        ac_mutex_unlock(&vs->lock);
        ac_mutex_unlock(&ps->lock);
        ac_mutex_unlock(&ss->lock);
        ac_mutex_unlock(&cs->lock);
        ac_mutex_unlock(&chain->lock);
        return AC_ERR_NOMEM;
    }

    /* Pass 2: serialize all sections after header */
    pos = (uint32_t)sizeof(ac_snapshot_header_t);

    serialize_claims(buf, &pos, cs);
    serialize_subnets(buf, &pos, ss);
    serialize_members(buf, &pos, ss);
    serialize_vpn(buf, &pos, vs);
    serialize_partitions(buf, &pos, ps);
    serialize_cross_rules(buf, &pos, ps);
    serialize_seq_table(buf, &pos, chain);
    serialize_dag_edges(buf, &pos, dag);

    ac_mutex_unlock(&dag->lock);
    ac_mutex_unlock(&vs->lock);
    ac_mutex_unlock(&ps->lock);
    ac_mutex_unlock(&ss->lock);
    ac_mutex_unlock(&cs->lock);
    ac_mutex_unlock(&chain->lock);

    /* Compute hash over payload (everything after header) */
    ac_crypto_sha256(buf + sizeof(ac_snapshot_header_t),
                     total_size - (uint32_t)sizeof(ac_snapshot_header_t),
                     snap->hash);

    /* Write header */
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = ac_cpu_to_le32(AC_SNAPSHOT_MAGIC);
    hdr.format_version = ac_cpu_to_le32(AC_SNAPSHOT_VERSION);
    hdr.snapshot_block = ac_cpu_to_le32(block_index);
    memcpy(hdr.state_hash, snap->hash, AC_HASH_LEN);
    hdr.total_size = ac_cpu_to_le32(total_size);
    memcpy(buf, &hdr, sizeof(hdr));

    snap->data = buf;
    snap->size = total_size;
    snap->block_index = block_index;

    ac_log_info("snapshot created at block %u, size=%u bytes",
                block_index, total_size);
    return AC_OK;
}

/* ================================================================== */
/*  Restore helpers                                                    */
/* ================================================================== */

static int restore_claims(const uint8_t *buf, uint32_t size,
                          uint32_t *pos, ac_claim_store_t *cs)
{
    uint32_t count, i;
    int rc;

    rc = read_u32(buf, size, pos, &count);
    if (rc != AC_OK) return rc;

    for (i = 0; i < count; i++) {
        ac_claim_record_t *cr;
        uint8_t claim_key[1 + AC_MAX_ADDR_LEN];

        if (*pos + (uint32_t)sizeof(ac_claim_record_t) > size)
            return AC_ERR_INVAL;

        cr = (ac_claim_record_t *)ac_alloc(sizeof(*cr), AC_MEM_NORMAL);
        if (!cr) return AC_ERR_NOMEM;

        memcpy(cr, buf + *pos, sizeof(*cr));
        *pos += (uint32_t)sizeof(*cr);

        claim_key[0] = cr->address.family;
        memcpy(claim_key + 1, cr->address.addr, AC_MAX_ADDR_LEN);

        rc = ac_hashmap_put(&cs->claims_map, claim_key,
                            1 + AC_MAX_ADDR_LEN, cr, NULL);
        if (rc != AC_OK) {
            ac_free(cr);
            return rc;
        }
        cs->claim_count++;
    }
    return AC_OK;
}

static int restore_subnets(const uint8_t *buf, uint32_t size,
                           uint32_t *pos, ac_subnet_store_t *ss)
{
    uint32_t count, i;
    int rc;

    rc = read_u32(buf, size, pos, &count);
    if (rc != AC_OK) return rc;

    for (i = 0; i < count; i++) {
        ac_subnet_record_t *sr;

        if (*pos + (uint32_t)sizeof(ac_subnet_record_t) > size)
            return AC_ERR_INVAL;

        sr = (ac_subnet_record_t *)ac_alloc(sizeof(*sr), AC_MEM_NORMAL);
        if (!sr) return AC_ERR_NOMEM;

        memcpy(sr, buf + *pos, sizeof(*sr));
        *pos += (uint32_t)sizeof(*sr);

        rc = ac_hashmap_put(&ss->subnet_map, sr->subnet_id,
                            AC_SUBNET_ID_LEN, sr, NULL);
        if (rc != AC_OK) {
            ac_free(sr);
            return rc;
        }
        ss->subnet_count++;
    }
    return AC_OK;
}

static int restore_members(const uint8_t *buf, uint32_t size,
                           uint32_t *pos, ac_subnet_store_t *ss)
{
    uint32_t count, i;
    int rc;

    rc = read_u32(buf, size, pos, &count);
    if (rc != AC_OK) return rc;

    for (i = 0; i < count; i++) {
        ac_subnet_member_t *sm;
        uint8_t member_key[AC_MEMBER_KEY_LEN];

        if (*pos + (uint32_t)sizeof(ac_subnet_member_t) > size)
            return AC_ERR_INVAL;

        sm = (ac_subnet_member_t *)ac_alloc(sizeof(*sm), AC_MEM_NORMAL);
        if (!sm) return AC_ERR_NOMEM;

        memcpy(sm, buf + *pos, sizeof(*sm));
        *pos += (uint32_t)sizeof(*sm);

        memcpy(member_key, sm->node_pubkey, AC_PUBKEY_LEN);
        memcpy(member_key + AC_PUBKEY_LEN, sm->subnet_id, AC_SUBNET_ID_LEN);

        rc = ac_hashmap_put(&ss->member_map, member_key,
                            AC_MEMBER_KEY_LEN, sm, NULL);
        if (rc != AC_OK) {
            ac_free(sm);
            return rc;
        }
        ss->member_count++;
    }
    return AC_OK;
}

static int restore_vpn(const uint8_t *buf, uint32_t size,
                       uint32_t *pos, ac_vpn_store_t *vs)
{
    uint32_t count, i;
    int rc;

    rc = read_u32(buf, size, pos, &count);
    if (rc != AC_OK) return rc;

    for (i = 0; i < count; i++) {
        ac_vpn_tunnel_t *vt;

        if (*pos + (uint32_t)sizeof(ac_vpn_tunnel_t) > size)
            return AC_ERR_INVAL;

        vt = (ac_vpn_tunnel_t *)ac_alloc(sizeof(*vt), AC_MEM_NORMAL);
        if (!vt) return AC_ERR_NOMEM;

        memcpy(vt, buf + *pos, sizeof(*vt));
        *pos += (uint32_t)sizeof(*vt);

        rc = ac_hashmap_put(&vs->tunnel_map, vt->remote_pubkey,
                            AC_PUBKEY_LEN, vt, NULL);
        if (rc != AC_OK) {
            ac_free(vt);
            return rc;
        }
    }
    return AC_OK;
}

static int restore_partitions(const uint8_t *buf, uint32_t size,
                              uint32_t *pos, ac_partition_store_t *ps)
{
    uint32_t count, i;
    int rc;

    rc = read_u32(buf, size, pos, &count);
    if (rc != AC_OK) return rc;

    for (i = 0; i < count; i++) {
        ac_partition_record_t *pr;
        uint32_t sub_count, j;

        pr = (ac_partition_record_t *)ac_zalloc(sizeof(*pr), AC_MEM_NORMAL);
        if (!pr) return AC_ERR_NOMEM;

        rc = read_bytes(buf, size, pos, pr->partition_id, AC_PARTITION_ID_LEN);
        if (rc != AC_OK) { ac_free(pr); return rc; }

        rc = read_u16(buf, size, pos, &pr->vlan_id);
        if (rc != AC_OK) { ac_free(pr); return rc; }

        rc = read_u8(buf, size, pos, &pr->active);
        if (rc != AC_OK) { ac_free(pr); return rc; }

        rc = read_u32(buf, size, pos, &sub_count);
        if (rc != AC_OK) { ac_free(pr); return rc; }

        pr->subnet_count = sub_count;
        pr->subnet_capacity = (sub_count > AC_PARTITION_SUBNET_INIT_CAP)
                             ? sub_count : AC_PARTITION_SUBNET_INIT_CAP;
        pr->subnet_ids = (uint8_t (*)[AC_SUBNET_ID_LEN])ac_alloc(
            pr->subnet_capacity * AC_SUBNET_ID_LEN, AC_MEM_NORMAL);
        if (!pr->subnet_ids && pr->subnet_capacity > 0) {
            ac_free(pr);
            return AC_ERR_NOMEM;
        }

        for (j = 0; j < sub_count; j++) {
            rc = read_bytes(buf, size, pos,
                            pr->subnet_ids[j], AC_SUBNET_ID_LEN);
            if (rc != AC_OK) {
                ac_free(pr->subnet_ids);
                ac_free(pr);
                return rc;
            }
        }

        rc = ac_hashmap_put(&ps->partition_map, pr->partition_id,
                            AC_PARTITION_ID_LEN, pr, NULL);
        if (rc != AC_OK) {
            ac_free(pr->subnet_ids);
            ac_free(pr);
            return rc;
        }
        ps->partition_count++;
    }
    return AC_OK;
}

static int restore_cross_rules(const uint8_t *buf, uint32_t size,
                               uint32_t *pos, ac_partition_store_t *ps)
{
    uint32_t count, i;
    int rc;

    rc = read_u32(buf, size, pos, &count);
    if (rc != AC_OK) return rc;

    for (i = 0; i < count; i++) {
        ac_cross_rule_t *cr;
        uint8_t rule_key[AC_CROSS_RULE_KEY_LEN];

        if (*pos + (uint32_t)sizeof(ac_cross_rule_t) > size)
            return AC_ERR_INVAL;

        cr = (ac_cross_rule_t *)ac_alloc(sizeof(*cr), AC_MEM_NORMAL);
        if (!cr) return AC_ERR_NOMEM;

        memcpy(cr, buf + *pos, sizeof(*cr));
        *pos += (uint32_t)sizeof(*cr);

        memcpy(rule_key, cr->partition_a, AC_PARTITION_ID_LEN);
        memcpy(rule_key + AC_PARTITION_ID_LEN,
               cr->partition_b, AC_PARTITION_ID_LEN);

        rc = ac_hashmap_put(&ps->cross_rule_map, rule_key,
                            AC_CROSS_RULE_KEY_LEN, cr, NULL);
        if (rc != AC_OK) {
            ac_free(cr);
            return rc;
        }
        ps->cross_rule_count++;
    }
    return AC_OK;
}

static int restore_seq_table(const uint8_t *buf, uint32_t size,
                             uint32_t *pos, ac_chain_t *chain)
{
    uint32_t count, i;
    int rc;

    rc = read_u32(buf, size, pos, &count);
    if (rc != AC_OK) return rc;

    for (i = 0; i < count; i++) {
        ac_seq_entry_t *se;

        if (*pos + (uint32_t)sizeof(ac_seq_entry_t) > size)
            return AC_ERR_INVAL;

        se = (ac_seq_entry_t *)ac_alloc(sizeof(*se), AC_MEM_NORMAL);
        if (!se) return AC_ERR_NOMEM;

        memcpy(se, buf + *pos, sizeof(*se));
        *pos += (uint32_t)sizeof(*se);

        rc = ac_hashmap_put(&chain->seq_map, se->pubkey,
                            AC_PUBKEY_LEN, se, NULL);
        if (rc != AC_OK) {
            ac_free(se);
            return rc;
        }
    }
    return AC_OK;
}

static int restore_dag_edges(const uint8_t *buf, uint32_t size,
                             uint32_t *pos, ac_dag_t *dag)
{
    uint32_t count, i;
    int rc;

    rc = read_u32(buf, size, pos, &count);
    if (rc != AC_OK) return rc;

    for (i = 0; i < count; i++) {
        uint8_t parent_key[AC_DAG_KEY_LEN];
        uint8_t child_key[AC_DAG_KEY_LEN];

        rc = read_bytes(buf, size, pos, parent_key, AC_DAG_KEY_LEN);
        if (rc != AC_OK) return rc;

        rc = read_bytes(buf, size, pos, child_key, AC_DAG_KEY_LEN);
        if (rc != AC_OK) return rc;

        /* Ensure both nodes exist before adding edge */
        (void)ac_dag_add_node(dag, parent_key[0], parent_key + 1);
        (void)ac_dag_add_node(dag, child_key[0], child_key + 1);

        rc = ac_dag_add_edge(dag,
                             parent_key[0], parent_key + 1,
                             child_key[0], child_key + 1);
        /* AC_ERR_EXIST is OK (duplicate), AC_ERR_INVAL means cycle */
        if (rc != AC_OK && rc != AC_ERR_EXIST)
            return rc;
    }
    return AC_OK;
}

/* ================================================================== */
/*  Restore                                                            */
/* ================================================================== */

int ac_snapshot_restore(const ac_snapshot_t *snap,
                        ac_chain_t *chain,
                        ac_claim_store_t *cs,
                        ac_subnet_store_t *ss,
                        ac_vpn_store_t *vs,
                        ac_partition_store_t *ps,
                        ac_dag_t *dag)
{
    ac_snapshot_header_t hdr;
    uint32_t pos;
    int rc;

    if (!snap || !snap->data || !chain || !cs || !ss || !vs || !ps || !dag)
        return AC_ERR_INVAL;

    if (snap->size < (uint32_t)sizeof(ac_snapshot_header_t))
        return AC_ERR_INVAL;

    /* Validate header */
    memcpy(&hdr, snap->data, sizeof(hdr));
    if (ac_le32_to_cpu(hdr.magic) != AC_SNAPSHOT_MAGIC)
        return AC_ERR_INVAL;
    if (ac_le32_to_cpu(hdr.format_version) != AC_SNAPSHOT_VERSION)
        return AC_ERR_INVAL;
    if (ac_le32_to_cpu(hdr.total_size) != snap->size)
        return AC_ERR_INVAL;

    /* Verify hash before restoring */
    rc = ac_snapshot_verify(snap);
    if (rc != AC_OK)
        return rc;

    pos = (uint32_t)sizeof(ac_snapshot_header_t);

    /* Restore each section in order (holding locks) */
    ac_mutex_lock(&chain->lock);
    ac_mutex_lock(&cs->lock);
    ac_mutex_lock(&ss->lock);
    ac_mutex_lock(&ps->lock);
    ac_mutex_lock(&vs->lock);
    ac_mutex_lock(&dag->lock);

    rc = restore_claims(snap->data, snap->size, &pos, cs);
    if (rc != AC_OK) goto unlock;

    rc = restore_subnets(snap->data, snap->size, &pos, ss);
    if (rc != AC_OK) goto unlock;

    rc = restore_members(snap->data, snap->size, &pos, ss);
    if (rc != AC_OK) goto unlock;

    rc = restore_vpn(snap->data, snap->size, &pos, vs);
    if (rc != AC_OK) goto unlock;

    rc = restore_partitions(snap->data, snap->size, &pos, ps);
    if (rc != AC_OK) goto unlock;

    rc = restore_cross_rules(snap->data, snap->size, &pos, ps);
    if (rc != AC_OK) goto unlock;

    rc = restore_seq_table(snap->data, snap->size, &pos, chain);
    if (rc != AC_OK) goto unlock;

    rc = restore_dag_edges(snap->data, snap->size, &pos, dag);

unlock:
    ac_mutex_unlock(&dag->lock);
    ac_mutex_unlock(&vs->lock);
    ac_mutex_unlock(&ps->lock);
    ac_mutex_unlock(&ss->lock);
    ac_mutex_unlock(&cs->lock);
    ac_mutex_unlock(&chain->lock);

    if (rc == AC_OK) {
        ac_log_info("snapshot restored at block %u", snap->block_index);
    } else {
        ac_log_error("snapshot restore failed at block %u: rc=%d",
                     snap->block_index, rc);
    }
    return rc;
}

/* ================================================================== */
/*  Verify                                                             */
/* ================================================================== */

int ac_snapshot_verify(const ac_snapshot_t *snap)
{
    uint8_t computed[AC_HASH_LEN];
    uint32_t payload_offset, payload_size;
    uint32_t i;
    uint32_t diff;

    if (!snap || !snap->data)
        return AC_ERR_INVAL;

    if (snap->size < (uint32_t)sizeof(ac_snapshot_header_t))
        return AC_ERR_INVAL;

    payload_offset = (uint32_t)sizeof(ac_snapshot_header_t);
    payload_size = snap->size - payload_offset;

    ac_crypto_sha256(snap->data + payload_offset, payload_size, computed);

    /* Constant-time comparison (P03: timing side-channel) */
    diff = 0;
    for (i = 0; i < AC_HASH_LEN; i++)
        diff |= (uint32_t)(computed[i] ^ snap->hash[i]);

    return (diff == 0) ? AC_OK : AC_ERR_CRYPTO;
}

/* ================================================================== */
/*  Free                                                               */
/* ================================================================== */

void ac_snapshot_free(ac_snapshot_t *snap)
{
    if (!snap)
        return;

    if (snap->data) {
        ac_crypto_zeroize(snap->data, snap->size);
        ac_free(snap->data);
        snap->data = NULL;
    }
    snap->size = 0;
    snap->block_index = 0;
    memset(snap->hash, 0, AC_HASH_LEN);
}

/* ================================================================== */
/*  Load from raw buffer                                               */
/* ================================================================== */

int ac_snapshot_load(ac_snapshot_t *snap, const uint8_t *data, uint32_t size)
{
    ac_snapshot_header_t hdr;

    if (!snap || !data)
        return AC_ERR_INVAL;

    if (size < (uint32_t)sizeof(ac_snapshot_header_t))
        return AC_ERR_INVAL;

    memset(snap, 0, sizeof(*snap));

    /* Parse and validate header */
    memcpy(&hdr, data, sizeof(hdr));

    if (ac_le32_to_cpu(hdr.magic) != AC_SNAPSHOT_MAGIC)
        return AC_ERR_INVAL;

    if (ac_le32_to_cpu(hdr.format_version) != AC_SNAPSHOT_VERSION)
        return AC_ERR_INVAL;

    if (ac_le32_to_cpu(hdr.total_size) != size)
        return AC_ERR_INVAL;

    /* Allocate and copy data */
    snap->data = (uint8_t *)ac_alloc(size, AC_MEM_NORMAL);
    if (!snap->data)
        return AC_ERR_NOMEM;

    memcpy(snap->data, data, size);
    snap->size = size;
    snap->block_index = ac_le32_to_cpu(hdr.snapshot_block);
    memcpy(snap->hash, hdr.state_hash, AC_HASH_LEN);

    return AC_OK;
}
