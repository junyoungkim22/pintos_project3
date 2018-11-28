#include "sup_pte.h"

unsigned sup_pte_hash(const struct hash_elem *elem, void *aux UNUSED)
{
	const struct sup_pte *p = hash_entry(elem, struct sup_pte, hash_elem);
	return hash_bytes(&p->vaddr, sizeof p->vaddr);
}

bool sup_pte_less(const struct hash_elem *elem1, const struct hash_elem *elem2, void *aux UNUSED)
{
	const struct sup_pte *p1 = hash_entry(elem1, struct sup_pte, hash_elem);
	const struct sup_pte *p2 = hash_entry(elem2, struct sup_pte, hash_elem);

	return p1->vaddr < p2->vaddr;
}

void
sup_pte_free(struct hash_elem *elem, void* aux UNUSED)
{
	struct sup_pte *spte = hash_entry(elem, struct sup_pte, hash_elem);
	if(!spte->allocated && !spte->is_mmap)
	{
		block_reset(spte->disk_index);		
	}
}
