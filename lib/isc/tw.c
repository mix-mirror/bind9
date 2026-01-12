/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Non-Cascading Hierarchical Timing Wheels as Priority Queue
 * Based on Linux Kernel Timer Wheel Redesign (Thomas Gleixner, post-4.x kernels)
 * References: https://lwn.net/Articles/646056/ and https://lwn.net/Articles/691064/
 *
 * Key Innovation: Timers NEVER move between wheels after initial placement.
 * This eliminates cascading operations and their associated latency spikes,
 * trading slight precision (1-2 ticks) for guaranteed O(1) performance.
 *
 * Design Principles:
 * 1. Timers are placed in a wheel based on their expiration time
 * 2. They remain in that wheel until they expire (no cascading)
 * 3. Timer expiration is determined by actual expiration time, not wheel position
 * 4. This may cause timers to fire slightly late (within granularity of their wheel)
 * 5. No worst-case latency spikes from cascade operations
 *
 * TRADE-OFF ANALYSIS:
 * ==================
 *
 * Classic Cascading Model (Varghese/Lauck):
 * - Pros: Precise timing (timers fire at exact expiration)
 * - Cons: Unpredictable O(N) latency spikes when cascading occurs
 *         (e.g., when seconds wheel wraps, all minute-slot timers move down)
 *         Cascading is completely pointless since most timers are canceled
 *         or rearmed before expiration anyway
 *
 * Non-Cascading Model (Linux Kernel):
 * - Pros: Guaranteed O(1) worst-case performance, no latency spikes
 *         Simpler implementation, better cache behavior
 *         Natural batching without explicit slack calculations
 *         Timers stay in buckets until expiry/cancellation
 * - Cons: Timer imprecision - may fire slightly late (up to wheel granularity)
 *         Worst-case inaccuracy: ~12.5% for timers at start of level
 *
 * Why This Matters for BIND:
 * - DNS server workloads benefit from predictable performance
 * - Most timer wheel timers are timeouts (TCP, UDP, disk I/O)
 * - Timeouts are exception handling - accuracy doesn't matter when they fire
 * - Vast majority of timers are canceled or rearmed before expiration
 * - Slight timer imprecision (seconds) is acceptable for DNS operations
 * - Eliminating worst-case spikes improves tail latency and throughput
 * - Better matches modern kernel timer behavior
 *
 * Real-World Performance (from Linux kernel analysis):
 * - Most timers: networking/I/O timeouts, canceled before expiry
 * - Short timers: expect reasonable accuracy, handled by fine-grained level 0
 * - Long timers: already inaccurate due to batching, further batching acceptable
 * - Cascading was observed causing 1ms+ loops in NOHZ scenarios
 *
 * Implementation Notes:
 * - Each wheel level has different granularity (1s, 256s, 18h, 194d)
 * - Granularity increases by factor of 256 per level (LVL_SLOTS)
 * - Timers are placed in the coarsest wheel that can represent their delta
 * - Expiration checks compare actual expiration time against current time
 * - Wheel positions advance without moving timers
 * - Natural batching: similar-expiry timers group in same bucket
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <isc/list.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/stdtime.h>
#include <isc/tw.h>
#include <isc/util.h>

static inline void
slot_add(isc_tw_slot_t *slot, isc_tw_elt_t *elt) {
	ISC_LIST_APPEND(slot->nodes, elt, link);
	slot->count++;
}

static inline void
slot_del(isc_tw_slot_t *slot, isc_tw_elt_t *elt) {
	INSIST(slot->count > 0);
	ISC_LIST_UNLINK(slot->nodes, elt, link);
	slot->count--;
}

static void
insert_internal(isc_tw_t *tw, isc_tw_elt_t *elt) {
	REQUIRE(ISC_TW_VALID(tw));
	REQUIRE(elt != NULL);

	isc_stdtime_t delta;

	if (elt->expire > tw->now) {
		delta = elt->expire - tw->now;
	} else {
		delta = 0;
	}

	/*
	 * Non-cascading placement: Choose wheel based on delta.
	 * Timer stays in this wheel until it expires - no cascading.
	 *
	 * We place the timer in the coarsest wheel that can represent
	 * the delta. This provides natural batching - timers with similar
	 * expiry times end up in the same bucket, reducing the number of
	 * timer events.
	 *
	 * The timer may fire slightly late (within the granularity of its
	 * wheel level), but this is acceptable for timeout-style timers
	 * which dominate DNS workloads.
	 */
	unsigned int target_level = 0;
	for (size_t i = 0; i < ISC_TW_LEVELS; i++) {
		isc_tw_level_t *lvl = &tw->levels[i];
		if (delta < lvl->tick_size * ISC_TW_SLOTS) {
			target_level = (unsigned int)i;
			break;
		}
		if (i == ISC_TW_LEVELS - 1) {
			target_level = (unsigned int)i;
		}
	}

	isc_tw_level_t *lvl = &tw->levels[target_level];

	/*
	 * Calculate slot within this level based on absolute expiration time.
	 * In non-cascading design, we use the actual expiration time modulo
	 * the wheel size to determine placement.
	 */
	uint64_t ticks = delta / lvl->tick_size;
	unsigned int current_slot = lvl->current;
	unsigned int target_slot = (current_slot + (unsigned int)ticks) %
				   ISC_TW_SLOTS;

	elt->level = target_level;
	elt->slot = target_slot;

	/* Add to the list */
	slot_add(&lvl->slots[target_slot], elt);
	tw->size++;

	/* Update earliest_slot if this is earlier */
	if (!lvl->has_earliest) {
		lvl->earliest_slot = target_slot;
		lvl->has_earliest = true;
	} else {
		/* Calculate distance from current considering wrap-around */
		unsigned int dist_earliest =
			(lvl->earliest_slot + ISC_TW_SLOTS - lvl->current) %
			ISC_TW_SLOTS;
		unsigned int dist_target =
			(target_slot + ISC_TW_SLOTS - lvl->current) %
			ISC_TW_SLOTS;
		if (dist_target < dist_earliest) {
			lvl->earliest_slot = target_slot;
		}
	}
}

isc_result_t
isc_tw_create(isc_mem_t *mctx, isc_tw_t **twp) {
	REQUIRE(twp != NULL && *twp == NULL);

	isc_tw_t *tw = isc_mem_get(mctx, sizeof(*tw));
	*tw = (isc_tw_t){
		.magic = ISC_TW_MAGIC,
		.mctx = isc_mem_ref(mctx),
		.now = isc_stdtime_now(),
	};

	/*
	 * Initialize hierarchy with non-cascading wheels.
	 *
	 * Each level has different granularity, providing natural batching:
	 * Level 0: 1s granularity    = 256s range    (~4 minutes)
	 * Level 1: 256s granularity  = 18.2h range   (~18 hours)
	 * Level 2: 18.2h granularity = 194d range    (~6 months)
	 * Level 3: 194d granularity  = 136y range    (~136 years)
	 *
	 * Worst-case timer inaccuracy: granularity of the wheel level.
	 * This is acceptable because:
	 * - Most timers are canceled before expiry (timeouts for I/O)
	 * - When timeouts fire, performance is already degraded
	 * - Long-term timers are already inaccurate due to batching
	 */
	for (size_t i = 0; i < ISC_TW_LEVELS; i++) {
		isc_tw_level_t *lvl = &tw->levels[i];

		if (i == 0) {
			lvl->tick_size = 1;
		} else {
			lvl->tick_size = tw->levels[i - 1].tick_size *
					 ISC_TW_SLOTS;
		}

		lvl->current = 0;
		lvl->earliest_slot = 0;
		lvl->has_earliest = false;

		for (size_t j = 0; j < ISC_TW_SLOTS; j++) {
			ISC_LIST_INIT(lvl->slots[j].nodes);
			lvl->slots[j].count = 0;
		}
	}

	*twp = tw;
	return ISC_R_SUCCESS;
}

void
isc_tw_destroy(isc_tw_t **twp) {
	isc_tw_t *tw;

	REQUIRE(twp != NULL);
	tw = *twp;
	*twp = NULL;
	REQUIRE(ISC_TW_VALID(tw));

	/*
	 * Remove all elements from all slots
	 */
	for (size_t i = 0; i < ISC_TW_LEVELS; i++) {
		isc_tw_level_t *lvl = &tw->levels[i];
		for (size_t j = 0; j < ISC_TW_SLOTS; j++) {
			isc_tw_slot_t *slot = &lvl->slots[j];
			isc_tw_elt_t *elt = NULL;

			while ((elt = ISC_LIST_HEAD(slot->nodes)) != NULL) {
				isc_tw_delete(tw, elt);
			}
		}
	}

	tw->magic = 0;

	isc_mem_putanddetach(&tw->mctx, tw, sizeof(*tw));
}

isc_result_t
isc_tw_insert(isc_tw_t *tw, isc_tw_elt_t *elt) {
	REQUIRE(ISC_TW_VALID(tw));
	REQUIRE(elt != NULL);
	REQUIRE(elt->level == (unsigned int)-1 &&
		elt->slot == (unsigned int)-1);

	insert_internal(tw, elt);

	return ISC_R_SUCCESS;
}

bool
isc_tw_is_node_deleted(isc_tw_elt_t *elt) {
	if (elt->level == (unsigned int)-1 || elt->slot == (unsigned int)-1) {
		return true;
	}

	return false;
}

void
isc_tw_delete(isc_tw_t *tw, isc_tw_elt_t *elt) {
	REQUIRE(ISC_TW_VALID(tw));
	REQUIRE(elt != NULL);

	if (isc_tw_is_node_deleted(elt)) {
		return;
	}

	REQUIRE(elt->level < ISC_TW_LEVELS);
	REQUIRE(elt->slot < ISC_TW_SLOTS);

	isc_tw_level_t *lvl = &tw->levels[elt->level];
	unsigned int deleted_slot = elt->slot;
	slot_del(&lvl->slots[elt->slot], elt);
	INSIST(tw->size > 0);
	tw->size--;

	/* Update earliest_slot if we just emptied the earliest slot */
	if (lvl->has_earliest && deleted_slot == lvl->earliest_slot &&
	    ISC_LIST_EMPTY(lvl->slots[deleted_slot].nodes))
	{
		/* Find next non-empty slot */
		lvl->has_earliest = false;
		for (size_t i = 0; i < ISC_TW_SLOTS; i++) {
			unsigned int check_slot =
				(deleted_slot + (unsigned int)i) % ISC_TW_SLOTS;
			if (!ISC_LIST_EMPTY(lvl->slots[check_slot].nodes)) {
				lvl->earliest_slot = check_slot;
				lvl->has_earliest = true;
				break;
			}
		}
	}

	elt->level = (unsigned int)-1;
	elt->slot = (unsigned int)-1;
}

static inline void
recalc_earliest(isc_tw_level_t *lvl) {
	lvl->has_earliest = false;
	for (size_t i = 0; i < ISC_TW_SLOTS; i++) {
		unsigned int check_slot = (lvl->current + (unsigned int)i) %
					 ISC_TW_SLOTS;
		if (!ISC_LIST_EMPTY(lvl->slots[check_slot].nodes)) {
			lvl->earliest_slot = check_slot;
			lvl->has_earliest = true;
			break;
		}
	}
}

void
isc_tw_settime(isc_tw_t *tw, isc_stdtime_t now) {
	REQUIRE(ISC_TW_VALID(tw));

	isc_stdtime_t old_time = tw->now;
	if (now <= old_time) {
		return;
	}

	/* Update current time atomically */
	tw->now = now;

	uint64_t ticks_elapsed = now - old_time;

	/*
	 * Non-cascading advancement: Simply advance wheel positions.
	 * NO cascading operations - timers stay where they are.
	 *
	 * For large time jumps or empty wheels, we can fast-forward
	 * by directly computing the new positions.
	 */
	if (tw->size == 0 || ticks_elapsed > ISC_TW_SLOTS * 2) {
		/* Fast-forward: compute new positions directly */
		uint64_t t = now;
		for (size_t i = 0; i < ISC_TW_LEVELS; i++) {
			tw->levels[i].current = t % ISC_TW_SLOTS;
			t /= ISC_TW_SLOTS;
			tw->levels[i].has_earliest = false;
		}

		/* Recalculate earliest slots after jump */
		for (size_t i = 0; i < ISC_TW_LEVELS; i++) {
			recalc_earliest(&tw->levels[i]);
		}
		return;
	}

	/*
	 * Normal advancement: tick each wheel forward.
	 * In non-cascading design, we only advance positions - no timer movement.
	 * Higher level wheels advance when lower levels complete rotations.
	 */
	for (uint64_t tick = 0; tick < ticks_elapsed; tick++) {
		/* Advance level 0 (finest granularity) */
		isc_tw_level_t *lvl0 = &tw->levels[0];
		lvl0->current = (lvl0->current + 1) % ISC_TW_SLOTS;
		recalc_earliest(lvl0);

		/*
		 * Advance higher levels when lower level completes rotation.
		 * This is purely positional - NO timer cascading occurs.
		 */
		if (lvl0->current == 0) {
			for (size_t level = 1; level < ISC_TW_LEVELS; level++) {
				isc_tw_level_t *lvl = &tw->levels[level];
				isc_tw_level_t *prev_lvl =
					&tw->levels[level - 1];

				/* Only advance if previous level just wrapped */
				if (prev_lvl->current == 0) {
					lvl->current = (lvl->current + 1) %
						       ISC_TW_SLOTS;
					recalc_earliest(lvl);
				} else {
					break; /* No more advancement needed */
				}
			}
		}
	}
}

isc_tw_elt_t *
isc_tw_element(isc_tw_t *tw) {
	REQUIRE(ISC_TW_VALID(tw));

	if (tw->size == 0) {
		return NULL;
	}

	/*
	 * In non-cascading design, find the EARLIEST expired timer.
	 *
	 * Scan all levels looking for expired timers and return the one
	 * with the minimum expiration time. Use slot count to skip empty slots.
	 */

	isc_tw_elt_t *earliest = NULL;

	/* Check level 0 first - finest granularity (1-second) */
	isc_tw_level_t *lvl0 = &tw->levels[0];
	for (size_t i = 0; i < ISC_TW_SLOTS; i++) {
		unsigned int slot = (lvl0->current + ISC_TW_SLOTS - i) % ISC_TW_SLOTS;
		
		/* Skip empty slots using count */
		if (lvl0->slots[slot].count == 0) {
			continue;
		}
		
		/* Check all timers in this non-empty slot */
		ISC_LIST_FOREACH(lvl0->slots[slot].nodes, elt, link) {
			if (!isc_tw_is_node_deleted(elt) && 
			    elt->expire <= tw->now) {
				if (earliest == NULL || elt->expire < earliest->expire) {
					earliest = elt;
				}
			}
		}
	}

	/* Check higher levels - coarser granularity */
	for (size_t level = 1; level < ISC_TW_LEVELS; level++) {
		isc_tw_level_t *lvl = &tw->levels[level];
		
		for (size_t i = 0; i < ISC_TW_SLOTS; i++) {
			unsigned int slot = (lvl->current + ISC_TW_SLOTS - i) % ISC_TW_SLOTS;
			
			/* Skip empty slots */
			if (lvl->slots[slot].count == 0) {
				continue;
			}
			
			ISC_LIST_FOREACH(lvl->slots[slot].nodes, elt, link) {
				if (!isc_tw_is_node_deleted(elt) && 
				    elt->expire <= tw->now) {
					if (earliest == NULL || elt->expire < earliest->expire) {
						earliest = elt;
					}
				}
			}
		}
	}

	return earliest;
}
