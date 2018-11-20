#include "fte.h"

uint8_t *get_frame(uint8_t *vaddr, enum palloc_flags flag, bool writable)
{
	uint8_t *kpage;
	bool success = false;
	struct fte *new_fte;
	struct sup_pte *new_sup_pte;

	kpage = palloc_get_page(PAL_USER | flag);
	if(kpage == NULL){
		//return success; //did not implement eviction/allocation
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
	hash_insert(&thread_current()->sup_page_table, &new_sup_pte->hash_elem);

	return kpage;
}
