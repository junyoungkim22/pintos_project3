#include "fte.h"

uint8_t *allocate_frame(void *vaddr, enum palloc_flags flag, bool writable)
{
	if(lock_held_by_current_thread(&frame_lock))
	{
		printf("1");
		lock_release(&frame_lock);
		sys_exit(-1);
	}
	lock_acquire(&frame_lock);
	uint8_t *kpage;
	bool success = false;
	struct fte *new_fte;
	struct fte *evict_fte;
	struct sup_pte *new_sup_pte;

	kpage = palloc_get_page(PAL_USER | flag);
	if(kpage == NULL){
		evict_fte = fte_to_evict();
		/*
		printf("evicting vaddr: %p\n", evict_fte->spte->vaddr);
		printf("new vaddr: %p\n", vaddr);
		*/
		if(!evict(evict_fte))
		{
			printf("Eviction failed\n");
			lock_release(&frame_lock);
			sys_exit(-1);
			return NULL;
		}
		kpage = palloc_get_page(PAL_USER | flag);
		if(kpage == NULL)
		{
			printf("Allocation after eviction failed\n");
			lock_release(&frame_lock);
			sys_exit(-1);
			return NULL;
		}
	}
	success = install_page(vaddr, kpage, writable);
	if(!success)
	{
		palloc_free_page(kpage);
		printf("Installation of page failed\n");
		lock_release(&frame_lock);
		sys_exit(-1);
		return NULL;
	}

	new_fte = malloc(sizeof (struct fte));
	new_fte->owner = thread_current();
	new_fte->frame = kpage;

	new_sup_pte = malloc(sizeof (struct sup_pte));
	new_sup_pte->vaddr = vaddr;
	new_sup_pte->access_time = timer_ticks();
	new_sup_pte->writable = writable;
	new_sup_pte->allocated = true;
	new_sup_pte->flag = flag;
	new_sup_pte->can_evict = true;
	new_sup_pte->is_mmap = false;
	
	new_fte->spte = new_sup_pte;

	hash_insert(&thread_current()->sup_page_table, &new_sup_pte->hash_elem);
	list_push_back(&frame_table, &new_fte->ft_elem);
	
	lock_release(&frame_lock);
	return kpage;
}

bool evict(struct fte *fte_to_evict)
{
	size_t index = bitmap_scan(sector_bitmap, 0, 8, false);
	if(index == BITMAP_ERROR)
	{
		printf("No space in swap!\n");
		return false;
	}
	write_to_block(fte_to_evict->frame, index);
	block_mark(index);
	pagedir_clear_page(fte_to_evict->owner->pagedir, fte_to_evict->spte->vaddr);
	palloc_free_page(fte_to_evict->frame);
	fte_to_evict->spte->disk_index = index;
	fte_to_evict->spte->allocated = false;
	list_remove(&fte_to_evict->ft_elem);
	free(fte_to_evict);
	return true;
}

bool load_mmap(struct sup_pte *spte)
{
	uint8_t *kpage;
	struct fte *evict_fte;
	struct fte *new_fte;
	struct mmap_info *spte_mmap_info;
	struct file *mmap_file;
	bool success;

	if(lock_held_by_current_thread(&frame_lock))
	{
		printf("2");
		lock_release(&frame_lock);
		sys_exit(-1);
	}
	lock_acquire(&frame_lock);
	if(spte->allocated)
	{
		lock_release(&frame_lock);
		return true;
	}
	spte_mmap_info = get_mmap_info(spte->vaddr);
	if(spte_mmap_info == NULL)
	{
		lock_release(&frame_lock);
		return false;
	}
	if(spte_mmap_info->size == 0)
	{
		lock_release(&frame_lock);
		sys_exit(-1);
	}
	kpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if(kpage == NULL){
		evict_fte = fte_to_evict();
		/*
		printf("evicting vaddr: %p\n", evict_fte->spte->vaddr);
		printf("new vaddr: %p\n", vaddr);
		*/
		if(!evict(evict_fte))
		{
			printf("Eviction failed\n");
			lock_release(&frame_lock);
			sys_exit(-1);
			return NULL;
		}
		kpage = palloc_get_page(PAL_USER | PAL_ZERO);
		if(kpage == NULL)
		{
			printf("Allocation after eviction failed\n");
			lock_release(&frame_lock);
			sys_exit(-1);
			return NULL;
		}
	}
	success = install_page(spte->vaddr, kpage, true);
	if(!success)
	{
		palloc_free_page(kpage);
		printf("Installation of page failed\n");
		lock_release(&frame_lock);
		sys_exit(-1);
		return NULL;
	}

	lock_acquire(&filesys_lock);
	//mmap_file = file_reopen(spte_mmap_info->mmap_file);
	mmap_file = spte_mmap_info->mmap_file;
	file_read_at(mmap_file, kpage, spte_mmap_info->size, spte_mmap_info->file_index);
	//file_close(mmap_file);
	lock_release(&filesys_lock);

	lock_release(&frame_lock);
}

bool load_sup_pte(struct sup_pte *spte)
{
	uint8_t *kpage;
	struct fte *evict_fte;
	struct fte *new_fte;
	bool success;

	if(lock_held_by_current_thread(&frame_lock))
	{
		printf("3");
		lock_release(&frame_lock);
		sys_exit(-1);
	}
	lock_acquire(&frame_lock);
	spte->can_evict = false;
	if(spte->allocated)
	{
		lock_release(&frame_lock);
		return true;
	}
	evict_fte = fte_to_evict();
	evict(evict_fte);
	kpage = palloc_get_page(PAL_USER | spte->flag);
	if(kpage == NULL)		
	{
		printf("Allocation after eviction failed\n");
		lock_release(&frame_lock);
		return false;
	}

	read_from_block(kpage, spte->disk_index);
	block_reset(spte->disk_index);

	success = install_page(spte->vaddr, kpage, spte->writable);
	if(!success)
	{
		palloc_free_page(kpage);
		lock_release(&frame_lock);
		/*
		printf("FAIL\n");
		lock_release(&frame_lock);
		sys_exit(-2);
		*/
		return success;
	}

	new_fte = malloc(sizeof (struct fte));
	new_fte->owner = thread_current();
	new_fte->frame = kpage;
	new_fte->spte = spte;
	
	spte->allocated = true;	
	list_push_back(&frame_table, &new_fte->ft_elem);
	lock_release(&frame_lock);
	return true;
}

struct fte *fte_to_evict()
{
	int n = list_size(&frame_table);
	struct fte *e;
	/*
	for(int i = 0; i < 2*n; i++)
	{
		e = clock_next_fte();
		if(!e->spte->can_evict)
		{
			continue;
		}
		if(e->owner == NULL)
		{
			printf("WTF\n");
			sys_exit(-1);
		}
		if(pagedir_is_accessed(e->owner->pagedir, e->spte->vaddr))
		{
			pagedir_set_accessed(e->owner->pagedir, e->spte->vaddr, false);
			continue;
		}
		return e;
	}
	*/
	struct list_elem *it;
	it = list_begin(&frame_table);
	for(int i = 0; i < 2 * (list_size(&frame_table)); i++)
	{
		e = list_entry(it, struct fte, ft_elem);
		if(e->spte->can_evict)
		{
			if(pagedir_is_accessed(e->owner->pagedir, e->spte->vaddr))
			{
				pagedir_set_accessed(e->owner->pagedir, e->spte->vaddr, false);
			}
			else
				return e;
		}
		it = list_next(it);
		if(it == list_end(&frame_table))
		{
			it = list_begin(&frame_table);
		}
	}
	printf("not found!\n");
	lock_release(&frame_lock);
	sys_exit(-1);
	return NULL;
}

/*
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
*/
