/*
 * ac_hashmap.h — Generic open-addressing hash map with binary keys
 *
 * Supports arbitrary-length binary keys (including embedded NULs).
 * Uses SipHash-2-4 for collision resistance (S14).
 * Geometric growth (2x at 75% load factor) for O(1) amortized ops.
 * Iterator supports safe in-place deletion via tombstone marking (S13).
 *
 * Thread safety: caller-managed. All public functions assume the
 * caller holds the appropriate lock per ac_platform.h lock ordering.
 *
 * Memory backend:
 *   - Kernel: vmalloc (large contiguous allocations)
 *   - Userspace: realloc
 *
 * Mitigates: S01,S02,S10,S13,S14
 */

#ifndef AC_HASHMAP_H
#define AC_HASHMAP_H

#include "ac_platform.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

#define AC_HASHMAP_INITIAL_CAP      64
#define AC_HASHMAP_LOAD_FACTOR_PCT  75
#define AC_HASHMAP_GROWTH_FACTOR    2

/* Slot states */
#define AC_SLOT_EMPTY       0
#define AC_SLOT_OCCUPIED    1
#define AC_SLOT_TOMBSTONE   2

/* ------------------------------------------------------------------ */
/*  Slot                                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t     state;          /* AC_SLOT_EMPTY / OCCUPIED / TOMBSTONE */
    uint8_t    *key;            /* allocated copy of key bytes          */
    uint32_t    key_len;        /* key length in bytes                  */
    void       *value;          /* caller-owned value pointer           */
    uint64_t    hash;           /* cached SipHash result                */
} ac_hashmap_slot_t;

/* ------------------------------------------------------------------ */
/*  Hash map                                                           */
/* ------------------------------------------------------------------ */

typedef struct {
    ac_hashmap_slot_t  *slots;
    uint32_t            capacity;       /* total slot count             */
    uint32_t            count;          /* occupied entries (not tombs) */
    uint32_t            tomb_count;     /* tombstone count              */
    uint32_t            max_capacity;   /* 0 = unlimited (userspace)    */
    uint8_t             sip_key[16];    /* SipHash secret key           */
} ac_hashmap_t;

/* ------------------------------------------------------------------ */
/*  Iterator                                                           */
/* ------------------------------------------------------------------ */

typedef struct {
    ac_hashmap_t   *map;
    uint32_t        index;              /* current slot index           */
} ac_hashmap_iter_t;

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                          */
/* ------------------------------------------------------------------ */

/*
 * ac_hashmap_init — Initialize a hash map.
 * @hm:           hash map to initialize
 * @initial_cap:  initial capacity (0 = AC_HASHMAP_INITIAL_CAP)
 * @max_cap:      maximum capacity (0 = unlimited). In kernel, set
 *                from module param to cap vmalloc usage (S15).
 *
 * Returns AC_OK or AC_ERR_NOMEM.
 */
int ac_hashmap_init(ac_hashmap_t *hm, uint32_t initial_cap, uint32_t max_cap);

/*
 * ac_hashmap_destroy — Free all map resources.
 * Does NOT free value pointers — caller must iterate and free first.
 * Frees all key copies.
 */
void ac_hashmap_destroy(ac_hashmap_t *hm);

/* ------------------------------------------------------------------ */
/*  Operations                                                         */
/* ------------------------------------------------------------------ */

/*
 * ac_hashmap_put — Insert or update an entry.
 * @key:      binary key (may contain embedded NULs)
 * @key_len:  key length in bytes
 * @value:    caller-owned pointer (not copied)
 * @old_value: if non-NULL and key existed, receives the old value pointer
 *
 * Returns AC_OK, AC_ERR_NOMEM (allocation/resize failed), or
 * AC_ERR_FULL (max_capacity reached and cannot resize).
 */
int ac_hashmap_put(ac_hashmap_t *hm,
                   const void *key, uint32_t key_len,
                   void *value, void **old_value);

/*
 * ac_hashmap_get — Look up an entry by key.
 * @key:      binary key
 * @key_len:  key length in bytes
 *
 * Returns the value pointer, or NULL if not found.
 */
void *ac_hashmap_get(const ac_hashmap_t *hm,
                     const void *key, uint32_t key_len);

/*
 * ac_hashmap_remove — Remove an entry by key.
 * @key:      binary key
 * @key_len:  key length in bytes
 *
 * Returns the removed value pointer (caller must free), or NULL if
 * not found. Marks the slot as tombstone for safe iteration (S13).
 */
void *ac_hashmap_remove(ac_hashmap_t *hm,
                        const void *key, uint32_t key_len);

/*
 * ac_hashmap_count — Number of entries in the map.
 */
uint32_t ac_hashmap_count(const ac_hashmap_t *hm);

/* ------------------------------------------------------------------ */
/*  Iterator                                                           */
/*                                                                     */
/*  Safe to call ac_hashmap_remove() on the current entry during       */
/*  iteration (tombstone marking preserves iteration order). Do NOT    */
/*  call ac_hashmap_put() during iteration — may trigger resize.       */
/* ------------------------------------------------------------------ */

/*
 * ac_hashmap_iter_init — Start iterating over all entries.
 */
void ac_hashmap_iter_init(ac_hashmap_iter_t *it, ac_hashmap_t *hm);

/*
 * ac_hashmap_iter_next — Advance to the next entry.
 * @key:      receives pointer to key bytes (not a copy — valid until remove)
 * @key_len:  receives key length
 * @value:    receives value pointer
 *
 * Returns 1 if an entry was found, 0 if iteration is complete.
 */
int ac_hashmap_iter_next(ac_hashmap_iter_t *it,
                         const void **key, uint32_t *key_len,
                         void **value);

/*
 * ac_hashmap_iter_remove — Remove the current entry during iteration.
 * Must be called after a successful ac_hashmap_iter_next().
 * Returns the removed value pointer.
 */
void *ac_hashmap_iter_remove(ac_hashmap_iter_t *it);

/* ------------------------------------------------------------------ */
/*  SipHash-2-4 (public for testing)                                   */
/* ------------------------------------------------------------------ */

/*
 * ac_siphash — Compute SipHash-2-4 of data with given key.
 * @key:  16-byte secret key
 * @data: input bytes
 * @len:  input length
 *
 * Returns 64-bit hash.
 */
uint64_t ac_siphash(const uint8_t key[16], const void *data, size_t len);

#endif /* AC_HASHMAP_H */
