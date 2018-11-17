#include <hash.h>
#include <debug.h>

struct sup_pte
{
	uint32_t* vaddr;
	uint64_t access_time;
	struct hash_elem hash_elem;
};

unsigned sup_pte_hash(const struct hash_elem *elem, void *aux UNUSED);
bool sup_pte_less(const struct hash_elem *elem1, const struct hash_elem *elem2, void *aux UNUSED);
