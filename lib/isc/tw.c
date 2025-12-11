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
 * Hierarchical Timing Wheels as Priority Queue
 * Based on "Hashed and Hierarchical Timing Wheels: Efficient Data Structures
 * for Implementing a Timer Facility" by George Varghese and Tony Lauck (1987)
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/tw.h>
#include <isc/urcu.h>
#include <isc/util.h>

static inline void
slot_add(isc_tw_slot_t *slot, isc_tw_elt_t *elt) {
	cds_list_add(&elt->list_node, &slot->head);
	slot->count++;
}

static inline void
slot_del(isc_tw_slot_t *slot, isc_tw_elt_t *elt) {
	cds_list_del(&elt->list_node);
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

	/* Find appropriate level */
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

	/* Calculate slot within this level */
	uint64_t ticks = delta / lvl->tick_size;
	unsigned int current_slot = lvl->current;
	unsigned int target_slot = (current_slot + (unsigned int)ticks) %
				   ISC_TW_SLOTS;

	elt->level = target_level;
	elt->slot = target_slot;

	/* Add to the list */
	slot_add(&lvl->slots[target_slot], elt);
	tw->size++;
}

isc_result_t
isc_tw_create(isc_mem_t *mctx, isc_tw_t **twp) {
	REQUIRE(twp != NULL && *twp == NULL);

	isc_tw_t *tw = isc_mem_get(mctx, sizeof(*tw));
	*tw = (isc_tw_t){
		.magic = ISC_TW_MAGIC,
		.mctx = isc_mem_ref(mctx),
	};

	/*
	 * Initialize hierarchy with CDS lists
	 * Level 0: 1 second per slot = 256 seconds (4.3 minutes)
	 * Level 1: 256 seconds per slot = 18.2 hours
	 * Level 2: 18.2 hours per slot = 194 days
	 * Level 3: 194 days per slot = 136 years
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

		for (size_t j = 0; j < ISC_TW_SLOTS; j++) {
			CDS_INIT_LIST_HEAD(&lvl->slots[j].head);
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

	tw->magic = 0;

	/*
	 * Remove all elements from all slots
	 */
	for (size_t i = 0; i < ISC_TW_LEVELS; i++) {
		isc_tw_level_t *lvl = &tw->levels[i];
		for (size_t j = 0; j < ISC_TW_SLOTS; j++) {
			isc_tw_slot_t *slot = &lvl->slots[j];
			isc_tw_elt_t *elt, *tmp;

			cds_list_for_each_entry_safe(elt, tmp, &slot->head,
						     list_node)
			{
				isc_tw_delete(tw, elt);
			}
		}
	}

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
	slot_del(&lvl->slots[elt->slot], elt);
	tw->size--;

	elt->level = (unsigned int)-1;
	elt->slot = (unsigned int)-1;
}

static void
cascade_slot(isc_tw_t *tw, unsigned int level, unsigned int slot_idx) {
	if (level >= ISC_TW_LEVELS) {
		return;
	}

	isc_tw_level_t *lvl = &tw->levels[level];
	isc_tw_slot_t *slot = &lvl->slots[slot_idx];

	isc_tw_elt_t *elt, *tmp;
	cds_list_for_each_entry_safe(elt, tmp, &slot->head, list_node) {
		if (isc_tw_is_node_deleted(elt)) {
			continue;
		}

		slot_del(slot, elt);
		tw->size--;

		elt->level = (unsigned int)-1;
		elt->slot = (unsigned int)-1;
		insert_internal(tw, elt);
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

	/* Limit iterations on huge time jumps */
	uint64_t max_ticks = ticks_elapsed;
	if (max_ticks > ISC_TW_SLOTS * 2) {
		max_ticks = ISC_TW_SLOTS * 2;
	}

	for (uint64_t tick = 0; tick < max_ticks; tick++) {
		/* Advance level 0 */
		isc_tw_level_t *lvl0 = &tw->levels[0];
		unsigned int new_current = (lvl0->current + 1) % ISC_TW_SLOTS;
		lvl0->current = new_current;

		/* Check cascading for higher levels */
		for (size_t level = 1; level < ISC_TW_LEVELS; level++) {
			isc_tw_level_t *lvl = &tw->levels[level];
			isc_tw_level_t *prev_lvl = &tw->levels[level - 1];

			if (prev_lvl->current == 0) {
				unsigned int current = lvl->current;
				cascade_slot(tw, (unsigned int)level, current);
				lvl->current = (current + 1) % ISC_TW_SLOTS;
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

	for (size_t level = 0; level < ISC_TW_LEVELS; level++) {
		isc_tw_level_t *lvl = &tw->levels[level];
		unsigned int current = lvl->current;

		/* Check current slot first */
		if (!cds_list_empty(&lvl->slots[current].head)) {
			isc_tw_elt_t *min = NULL;
			isc_tw_elt_t *elt;

			cds_list_for_each_entry(elt, &lvl->slots[current].head,
						list_node) {
				if (isc_tw_is_node_deleted(elt)) {
					continue;
				}

				if (min == NULL) {
					min = elt;
				} else if (elt->expire < min->expire) {
					min = elt;
				}
			}

			if (min != NULL) {
				return min;
			}
		}

		/* For higher levels we only inspect the current slot; lower
		 * levels can walk forward slots to find the next earliest
		 * element. Cascading of higher levels is driven by time
		 * advancement in isc_tw_settime().
		 */
		if (level == 0) {
			for (size_t offset = 1; offset < ISC_TW_SLOTS; offset++) {
				unsigned int slot_idx = (current +
							 (unsigned int)offset) %
							ISC_TW_SLOTS;

				if (!cds_list_empty(&lvl->slots[slot_idx].head)) {
					isc_tw_elt_t *min = NULL;
					isc_tw_elt_t *elt;

					cds_list_for_each_entry(
						elt, &lvl->slots[slot_idx].head,
						list_node) {
						if (isc_tw_is_node_deleted(elt)) {
							continue;
						}

						if (min == NULL) {
							min = elt;
						} else if (elt->expire <
							   min->expire) {
							min = elt;
						}
					}

					if (min != NULL) {
						return min;
					}
				}
			}
		}
	}

	return NULL;
}
