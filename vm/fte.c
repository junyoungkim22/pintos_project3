#include "fte.h"

uint8_t *allocate_frame(void *vaddr, enum palloc_flags flag, bool writable)
{
	uint8_t *kpage;
	bool success = false;
	struct fte *new_fte;
	struct fte *evict_fte;
	struct sup_pte *new_sup_pte;

	kpage = palloc_get_page(PAL_USER | flag);
	if(kpage == NULL){
		//return success; //did not implement eviction/allocation
		printf("ran out of pages...\n\n");
		evict_fte = fte_to_evict();
		pagedir_clear_page(evict_fte->owner->pagedir, evict_fte->frame);
		printf("evict fte process name: %s\n", evict_fte->owner->name);
		return NULL;
	}
	//printf("allocating... %p\n", vaddr);
	success = install_page(vaddr, kpage, writable);
	if(!success)
	{
		palloc_free_page(kpage);
		//return success;
		return NULL;
	}

	new_fte = malloc(sizeof (struct fte));
	new_fte->owner = thread_current();
	new_fte->frame = kpage;
	list_push_back(&frame_table, &new_fte->ft_elem);

	new_sup_pte = malloc(sizeof (struct sup_pte));
	new_sup_pte->vaddr = vaddr;
	new_sup_pte->access_time = timer_ticks();
	new_sup_pte->writable = writable;
	new_sup_pte->allocated = true;
	
	new_fte->spte = new_sup_pte;

	hash_insert(&thread_current()->sup_page_table, &new_sup_pte->hash_elem);

	return kpage;
}

struct fte *fte_to_evict()
{
	int n = list_size(&frame_table);
	struct fte *e;
	printf("list size: %d\n", n);
	for(int i = 0; i < 2*n; i++)
	{
		e = clock_next_fte();
		printf("owner is : %s, %p\n", e->owner->name, e->spte->vaddr);
		if(pagedir_is_accessed(e->owner->pagedir, e->spte->vaddr))
		{
			//printf("accesssss\n");
			pagedir_set_accessed(e->owner->pagedir, e->spte->vaddr, false);
			continue;
		}
		//printf("no accesssss\n");
		return e;
	}
	return NULL;
}

struct fte *clock_next_fte()
{
	struct fte *ret;
	if(list_empty(&frame_table))
	{
		printf("List is empty\n");
		return NULL;
	}
	if(clock_pointer == list_end(&frame_table))
	{
		clock_pointer = list_begin(&frame_table);
	}
	ret = list_entry(clock_pointer, struct fte, ft_elem);
	clock_pointer = list_next(clock_pointer);
	return ret;
}
