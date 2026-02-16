/*
 * ac_hashmap.c — Generic open-addressing hash map implementation
 *
 * Open addressing with linear probing and Robin Hood heuristic.
 * SipHash-2-4 for collision-resistant hashing of binary keys.
 * Geometric growth (2x) at 75% load factor.
 * Tombstone-based deletion for safe iteration.
 *
 * Mitigates: S01,S02,S10,S13,S14
 */

#include "ac_hashmap.h"
#include "ac_crypto.h"

/* ================================================================== */
/*  SipHash-2-4 implementation                                         */
/* ================================================================== */

#define SIPROUND                                        \
    do {                                                \
        v0 += v1; v1 = (v1 << 13) | (v1 >> 51);       \
        v1 ^= v0; v0 = (v0 << 32) | (v0 >> 32);       \
        v2 += v3; v3 = (v3 << 16) | (v3 >> 48);       \
        v3 ^= v2;                                      \
        v0 += v3; v3 = (v3 << 21) | (v3 >> 43);       \
        v3 ^= v0;                                      \
        v2 += v1; v1 = (v1 << 17) | (v1 >> 47);       \
        v1 ^= v2; v2 = (v2 << 32) | (v2 >> 32);       \
    } while (0)

static uint64_t read_u64_le(const uint8_t *p)
{
    return (uint64_t)p[0]       | ((uint64_t)p[1] << 8)  |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

uint64_t ac_siphash(const uint8_t key[16], const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    const uint8_t *end = p + (len & ~7ULL);
    uint64_t k0 = read_u64_le(key);
    uint64_t k1 = read_u64_le(key + 8);
    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;
    uint64_t m;
    uint64_t b = ((uint64_t)len) << 56;

    while (p < end) {
        m = read_u64_le(p);
        v3 ^= m;
        SIPROUND;
        SIPROUND;
        v0 ^= m;
        p += 8;
    }

    switch (len & 7) {
    case 7: b |= ((uint64_t)p[6]) << 48; /* fall through */
    case 6: b |= ((uint64_t)p[5]) << 40; /* fall through */
    case 5: b |= ((uint64_t)p[4]) << 32; /* fall through */
    case 4: b |= ((uint64_t)p[3]) << 24; /* fall through */
    case 3: b |= ((uint64_t)p[2]) << 16; /* fall through */
    case 2: b |= ((uint64_t)p[1]) << 8;  /* fall through */
    case 1: b |= ((uint64_t)p[0]);        break;
    case 0: break;
    }

    v3 ^= b;
    SIPROUND;
    SIPROUND;
    v0 ^= b;

    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;

    return v0 ^ v1 ^ v2 ^ v3;
}

/* ================================================================== */
/*  Internal helpers                                                   */
/* ================================================================== */

static uint64_t compute_hash(const ac_hashmap_t *hm,
                              const void *key, uint32_t key_len)
{
    return ac_siphash(hm->sip_key, key, key_len);
}

static uint32_t slot_index(uint64_t hash, uint32_t capacity)
{
    return (uint32_t)(hash % (uint64_t)capacity);
}

/*
 * probe_distance — How far a slot is from its ideal position.
 * Used for Robin Hood insertion to limit worst-case probe length.
 */
static uint32_t probe_distance(uint32_t capacity, uint64_t hash,
                                uint32_t current)
{
    uint32_t ideal = slot_index(hash, capacity);
    if (current >= ideal)
        return current - ideal;
    return capacity - ideal + current;
}

static int key_eq(const ac_hashmap_slot_t *slot,
                  const void *key, uint32_t key_len, uint64_t hash)
{
    if (slot->hash != hash)
        return 0;
    if (slot->key_len != key_len)
        return 0;
    return memcmp(slot->key, key, key_len) == 0;
}

static int needs_resize(const ac_hashmap_t *hm)
{
    uint64_t used = (uint64_t)hm->count + (uint64_t)hm->tomb_count;
    return (used * 100) >= ((uint64_t)hm->capacity * AC_HASHMAP_LOAD_FACTOR_PCT);
}

/* Allocate a slot array */
static ac_hashmap_slot_t *alloc_slots(uint32_t capacity)
{
    size_t sz = (size_t)capacity * sizeof(ac_hashmap_slot_t);
    ac_hashmap_slot_t *s = (ac_hashmap_slot_t *)ac_zalloc(sz, AC_MEM_NORMAL);
    return s;
}

/* Free a single slot's key */
static void free_slot_key(ac_hashmap_slot_t *slot)
{
    if (slot->key) {
        ac_free(slot->key);
        slot->key = NULL;
    }
}

/* Copy key bytes into a new allocation */
static uint8_t *dup_key(const void *key, uint32_t key_len)
{
    uint8_t *k;
    if (key_len == 0)
        return NULL;
    k = (uint8_t *)ac_alloc(key_len, AC_MEM_NORMAL);
    if (k)
        memcpy(k, key, key_len);
    return k;
}

/*
 * resize — Rehash all entries into a new table of the given capacity.
 * Tombstones are discarded during resize.
 */
static int resize(ac_hashmap_t *hm, uint32_t new_cap)
{
    ac_hashmap_slot_t *old_slots = hm->slots;
    uint32_t old_cap = hm->capacity;
    ac_hashmap_slot_t *new_slots;
    uint32_t i;

    if (hm->max_capacity > 0 && new_cap > hm->max_capacity) {
        new_cap = hm->max_capacity;
        if (new_cap <= old_cap)
            return AC_ERR_FULL;
    }

    new_slots = alloc_slots(new_cap);
    if (!new_slots) {
        ac_log_error("hashmap resize to %u failed: OOM", new_cap);
        return AC_ERR_NOMEM;
    }

    hm->slots = new_slots;
    hm->capacity = new_cap;
    hm->count = 0;
    hm->tomb_count = 0;

    for (i = 0; i < old_cap; i++) {
        ac_hashmap_slot_t *os = &old_slots[i];
        if (os->state != AC_SLOT_OCCUPIED)
            continue;

        /* Insert into new table — no resize can occur here */
        {
            uint32_t idx = slot_index(os->hash, new_cap);
            uint32_t dist = 0;
            ac_hashmap_slot_t incoming;
            incoming.state = AC_SLOT_OCCUPIED;
            incoming.key = os->key;
            incoming.key_len = os->key_len;
            incoming.value = os->value;
            incoming.hash = os->hash;

            for (;;) {
                ac_hashmap_slot_t *ns = &new_slots[idx];
                if (ns->state != AC_SLOT_OCCUPIED) {
                    *ns = incoming;
                    hm->count++;
                    break;
                }
                /* Robin Hood: swap if current entry has shorter probe */
                {
                    uint32_t existing_dist = probe_distance(new_cap,
                                                             ns->hash, idx);
                    if (dist > existing_dist) {
                        ac_hashmap_slot_t tmp = *ns;
                        *ns = incoming;
                        incoming = tmp;
                        dist = existing_dist;
                    }
                }
                idx = (idx + 1) % new_cap;
                dist++;
            }
        }
    }

    /* Free old slot array (keys moved, not freed) */
    ac_free(old_slots);
    return AC_OK;
}

/* ================================================================== */
/*  Public API                                                         */
/* ================================================================== */

int ac_hashmap_init(ac_hashmap_t *hm, uint32_t initial_cap, uint32_t max_cap)
{
    if (!hm)
        return AC_ERR_INVAL;

    memset(hm, 0, sizeof(*hm));

    if (initial_cap == 0)
        initial_cap = AC_HASHMAP_INITIAL_CAP;

    /* Round up to power of 2 for modulus efficiency is not required
     * for correctness with modulo, but ensure minimum */
    if (initial_cap < 8)
        initial_cap = 8;

    hm->max_capacity = max_cap;

    if (max_cap > 0 && initial_cap > max_cap)
        initial_cap = max_cap;

    hm->slots = alloc_slots(initial_cap);
    if (!hm->slots) {
        ac_log_error("hashmap init (%u slots): OOM", initial_cap);
        return AC_ERR_NOMEM;
    }

    hm->capacity = initial_cap;
    hm->count = 0;
    hm->tomb_count = 0;

    /* Generate random SipHash key for this instance */
    if (ac_crypto_random(hm->sip_key, sizeof(hm->sip_key)) != AC_OK) {
        /* Fallback: deterministic but unique-ish key */
        memset(hm->sip_key, 0x42, sizeof(hm->sip_key));
        ac_log_warn("hashmap: random SipHash key failed, using fallback");
    }

    ac_log_debug("hashmap init: cap=%u max=%u", initial_cap, max_cap);
    return AC_OK;
}

void ac_hashmap_destroy(ac_hashmap_t *hm)
{
    uint32_t i;

    if (!hm || !hm->slots)
        return;

    for (i = 0; i < hm->capacity; i++) {
        free_slot_key(&hm->slots[i]);
    }

    ac_free(hm->slots);
    hm->slots = NULL;
    hm->capacity = 0;
    hm->count = 0;
    hm->tomb_count = 0;
    ac_log_debug("hashmap destroyed");
}

int ac_hashmap_put(ac_hashmap_t *hm,
                   const void *key, uint32_t key_len,
                   void *value, void **old_value)
{
    uint64_t hash;
    uint32_t idx, dist;
    int rc;
    ac_hashmap_slot_t incoming;
    int first_tomb = -1;

    if (!hm || !key || key_len == 0)
        return AC_ERR_INVAL;

    /* Resize if needed before insertion */
    if (needs_resize(hm)) {
        uint32_t new_cap = hm->capacity * AC_HASHMAP_GROWTH_FACTOR;
        if (new_cap < hm->capacity) /* overflow */
            new_cap = hm->capacity;
        rc = resize(hm, new_cap);
        if (rc != AC_OK && rc != AC_ERR_FULL)
            return rc;
        /* AC_ERR_FULL from resize means at max_capacity — try to proceed
         * if there are tombstones to reclaim */
        if (rc == AC_ERR_FULL && hm->tomb_count > 0) {
            rc = resize(hm, hm->capacity); /* rehash in place, clear tombs */
            if (rc != AC_OK)
                return AC_ERR_FULL;
        } else if (rc == AC_ERR_FULL && hm->count >= hm->capacity) {
            return AC_ERR_FULL;
        }
    }

    hash = compute_hash(hm, key, key_len);
    idx = slot_index(hash, hm->capacity);
    dist = 0;

    for (;;) {
        ac_hashmap_slot_t *slot = &hm->slots[idx];

        if (slot->state == AC_SLOT_EMPTY) {
            /* Use first tombstone if we found one, otherwise this empty slot */
            if (first_tomb >= 0) {
                slot = &hm->slots[first_tomb];
                hm->tomb_count--;
            }
            slot->key = dup_key(key, key_len);
            if (!slot->key)
                return AC_ERR_NOMEM;
            slot->key_len = key_len;
            slot->value = value;
            slot->hash = hash;
            slot->state = AC_SLOT_OCCUPIED;
            hm->count++;
            if (old_value)
                *old_value = NULL;
            return AC_OK;
        }

        if (slot->state == AC_SLOT_TOMBSTONE) {
            if (first_tomb < 0)
                first_tomb = (int)idx;
            idx = (idx + 1) % hm->capacity;
            dist++;
            if (dist >= hm->capacity)
                return AC_ERR_FULL;
            continue;
        }

        /* Occupied slot — check for duplicate key */
        if (key_eq(slot, key, key_len, hash)) {
            if (old_value)
                *old_value = slot->value;
            slot->value = value;
            return AC_OK;
        }

        /* Robin Hood: if current entry has shorter probe, swap */
        {
            uint32_t existing_dist = probe_distance(hm->capacity,
                                                     slot->hash, idx);
            if (dist > existing_dist) {
                /* For simplicity with tombstones, use first_tomb if available */
                if (first_tomb >= 0) {
                    ac_hashmap_slot_t *ts = &hm->slots[first_tomb];
                    ts->key = dup_key(key, key_len);
                    if (!ts->key)
                        return AC_ERR_NOMEM;
                    ts->key_len = key_len;
                    ts->value = value;
                    ts->hash = hash;
                    ts->state = AC_SLOT_OCCUPIED;
                    hm->count++;
                    hm->tomb_count--;
                    if (old_value)
                        *old_value = NULL;
                    return AC_OK;
                }
                /* Full Robin Hood swap */
                incoming.state = AC_SLOT_OCCUPIED;
                incoming.key = dup_key(key, key_len);
                if (!incoming.key)
                    return AC_ERR_NOMEM;
                incoming.key_len = key_len;
                incoming.value = value;
                incoming.hash = hash;
                if (old_value)
                    *old_value = NULL;

                /* Swap with current slot */
                {
                    ac_hashmap_slot_t tmp = *slot;
                    *slot = incoming;
                    incoming = tmp;
                }
                hm->count++;

                /* Re-insert displaced entry */
                key = incoming.key;
                key_len = incoming.key_len;
                value = incoming.value;
                hash = incoming.hash;
                /* Continue probing for displaced entry — but it already
                 * owns its key, so don't dup again. We need special handling */
                idx = (idx + 1) % hm->capacity;
                dist = probe_distance(hm->capacity, hash, idx);

                /* Insert displaced without dup_key since it owns its key */
                for (;;) {
                    ac_hashmap_slot_t *s2 = &hm->slots[idx];
                    if (s2->state != AC_SLOT_OCCUPIED) {
                        if (s2->state == AC_SLOT_TOMBSTONE)
                            hm->tomb_count--;
                        s2->state = AC_SLOT_OCCUPIED;
                        s2->key = incoming.key;
                        s2->key_len = incoming.key_len;
                        s2->value = incoming.value;
                        s2->hash = incoming.hash;
                        /* count already incremented for new entry;
                         * displaced entry was already counted */
                        return AC_OK;
                    }
                    {
                        uint32_t ed = probe_distance(hm->capacity,
                                                      s2->hash, idx);
                        if (dist > ed) {
                            ac_hashmap_slot_t tmp2 = *s2;
                            s2->key = incoming.key;
                            s2->key_len = incoming.key_len;
                            s2->value = incoming.value;
                            s2->hash = incoming.hash;
                            incoming = tmp2;
                            dist = ed;
                        }
                    }
                    idx = (idx + 1) % hm->capacity;
                    dist++;
                }
            }
        }

        idx = (idx + 1) % hm->capacity;
        dist++;
        if (dist >= hm->capacity)
            return AC_ERR_FULL;
    }
}

void *ac_hashmap_get(const ac_hashmap_t *hm,
                     const void *key, uint32_t key_len)
{
    uint64_t hash;
    uint32_t idx, dist;

    if (!hm || !hm->slots || !key || key_len == 0)
        return NULL;

    hash = compute_hash(hm, key, key_len);
    idx = slot_index(hash, hm->capacity);
    dist = 0;

    for (;;) {
        const ac_hashmap_slot_t *slot = &hm->slots[idx];

        if (slot->state == AC_SLOT_EMPTY)
            return NULL;

        if (slot->state == AC_SLOT_OCCUPIED && key_eq(slot, key, key_len, hash))
            return slot->value;

        /* Robin Hood: if probe distance exceeds what this slot's entry
         * would have, the key doesn't exist */
        if (slot->state == AC_SLOT_OCCUPIED) {
            uint32_t sd = probe_distance(hm->capacity, slot->hash, idx);
            if (dist > sd)
                return NULL;
        }

        idx = (idx + 1) % hm->capacity;
        dist++;
        if (dist >= hm->capacity)
            return NULL;
    }
}

void *ac_hashmap_remove(ac_hashmap_t *hm,
                        const void *key, uint32_t key_len)
{
    uint64_t hash;
    uint32_t idx, dist;

    if (!hm || !hm->slots || !key || key_len == 0)
        return NULL;

    hash = compute_hash(hm, key, key_len);
    idx = slot_index(hash, hm->capacity);
    dist = 0;

    for (;;) {
        ac_hashmap_slot_t *slot = &hm->slots[idx];

        if (slot->state == AC_SLOT_EMPTY)
            return NULL;

        if (slot->state == AC_SLOT_OCCUPIED && key_eq(slot, key, key_len, hash)) {
            void *val = slot->value;
            free_slot_key(slot);
            slot->value = NULL;
            slot->state = AC_SLOT_TOMBSTONE;
            slot->key_len = 0;
            hm->count--;
            hm->tomb_count++;
            return val;
        }

        if (slot->state == AC_SLOT_OCCUPIED) {
            uint32_t sd = probe_distance(hm->capacity, slot->hash, idx);
            if (dist > sd)
                return NULL;
        }

        idx = (idx + 1) % hm->capacity;
        dist++;
        if (dist >= hm->capacity)
            return NULL;
    }
}

uint32_t ac_hashmap_count(const ac_hashmap_t *hm)
{
    if (!hm)
        return 0;
    return hm->count;
}

/* ================================================================== */
/*  Iterator                                                           */
/* ================================================================== */

void ac_hashmap_iter_init(ac_hashmap_iter_t *it, ac_hashmap_t *hm)
{
    if (!it)
        return;
    it->map = hm;
    it->index = 0;
}

int ac_hashmap_iter_next(ac_hashmap_iter_t *it,
                         const void **key, uint32_t *key_len,
                         void **value)
{
    if (!it || !it->map || !it->map->slots)
        return 0;

    while (it->index < it->map->capacity) {
        ac_hashmap_slot_t *slot = &it->map->slots[it->index];
        it->index++;

        if (slot->state == AC_SLOT_OCCUPIED) {
            if (key)
                *key = slot->key;
            if (key_len)
                *key_len = slot->key_len;
            if (value)
                *value = slot->value;
            return 1;
        }
    }

    return 0;
}

void *ac_hashmap_iter_remove(ac_hashmap_iter_t *it)
{
    ac_hashmap_slot_t *slot;
    void *val;

    if (!it || !it->map || it->index == 0)
        return NULL;

    /* iter_next incremented index past the current entry */
    slot = &it->map->slots[it->index - 1];
    if (slot->state != AC_SLOT_OCCUPIED)
        return NULL;

    val = slot->value;
    free_slot_key(slot);
    slot->value = NULL;
    slot->state = AC_SLOT_TOMBSTONE;
    slot->key_len = 0;
    it->map->count--;
    it->map->tomb_count++;
    return val;
}
