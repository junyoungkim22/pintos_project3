#include <hash.h>
#include <debug.h>
#include "threads/palloc.h"
#include "threads/synch.h"

//Define bottom of area where user program can access via memory
#define USER_ACCESS_LIMIT 0x08048000
#define USER_STACK_LIMIT PHYS_BASE-(1<<23)

struct lock filesys_lock;

struct sup_pte
{
	uint8_t* vaddr;
	bool writable;
	bool allocated;
	bool can_evict;
	bool is_mmap;
	size_t disk_index;
	enum palloc_flags flag;
	struct hash_elem hash_elem;
};

unsigned sup_pte_hash(const struct hash_elem *elem, void *aux UNUSED);
bool sup_pte_less(const struct hash_elem *elem1, const struct hash_elem *elem2, void *aux UNUSED);
void sup_pte_free(struct hash_elem*, void*);
