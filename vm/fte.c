#include "fte.h"

uint8_t *allocate_frame(void *vaddr, enum palloc_flags flag, bool writable)
{
	uint8_t *kpage;
	bool success = false;
	struct fte *new_fte;
	struct fte *evict_fte;
	struct sup_pte *new_sup_pte;

	lock_acquire(&frame_lock);
	kpage = get_frame(flag);
	ASSERT(kpage != NULL);
	success = install_page(vaddr, kpage, writable);
	ASSERT(success);

	new_fte = malloc(sizeof (struct fte));
	new_fte->owner = thread_current();
	new_fte->frame = kpage;

	new_sup_pte = malloc(sizeof (struct sup_pte));
	new_sup_pte->vaddr = vaddr;
	new_sup_pte->writable = writable;
	new_sup_pte->flag = flag;
	new_sup_pte->can_evict = true;
	new_sup_pte->is_mmap = false;
	
	new_fte->spte = new_sup_pte;

	hash_insert(&thread_current()->sup_page_table, &new_sup_pte->hash_elem);
	list_push_back(&frame_table, &new_fte->ft_elem);
	
	new_sup_pte->allocated = true;
	lock_release(&frame_lock);
	return kpage;
}

bool evict(struct fte *fte_to_evict)
{
	size_t index;
	struct file *mmap_file;
	struct mmap_info *spte_mmap_info;

	ASSERT(fte_to_evict != NULL);

	if(fte_to_evict->spte->is_mmap && pagedir_is_dirty(fte_to_evict->owner->pagedir, fte_to_evict->spte->vaddr))
	{
		lock_acquire(&filesys_lock);
		spte_mmap_info = get_mmap_info(fte_to_evict->spte->vaddr);
		mmap_file = spte_mmap_info->mmap_file;
		file_write_at(mmap_file, fte_to_evict->frame, spte_mmap_info->size, spte_mmap_info->file_index);
		lock_release(&filesys_lock);
	}
	else 
	{
		index = bitmap_scan(sector_bitmap, 0, 8, false);
		ASSERT(index != BITMAP_ERROR);
		write_to_block(fte_to_evict->frame, index);
		block_mark(index);
		fte_to_evict->spte->disk_index = index;
	}
	pagedir_clear_page(fte_to_evict->owner->pagedir, fte_to_evict->spte->vaddr);
	palloc_free_page(fte_to_evict->frame);
	list_remove(&fte_to_evict->ft_elem);
	fte_to_evict->spte->allocated = false;
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
	size_t read_bytes;
	bool success;

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
		return false;
	}
	kpage = get_frame(PAL_ZERO);
	ASSERT(kpage != NULL);
	success = install_page(spte->vaddr, kpage, true);
	if(!success)
	{
		palloc_free_page(kpage);
		printf("Installation of page failed\n");
		lock_release(&frame_lock);
		return false;
	}

	lock_acquire(&filesys_lock);
	mmap_file = spte_mmap_info->mmap_file;
	read_bytes = spte_mmap_info->size;
	file_read_at(mmap_file, kpage, read_bytes, spte_mmap_info->file_index);
	memset(kpage + read_bytes, 0, PGSIZE - read_bytes);
	lock_release(&filesys_lock);

	new_fte = malloc(sizeof (struct fte));
	new_fte->owner = thread_current();
	new_fte->frame = kpage;
	new_fte->spte = spte;
	list_push_back(&frame_table, &new_fte->ft_elem);
	spte->allocated = true;	

	lock_release(&frame_lock);
	return true;
}

bool load_sup_pte(struct sup_pte *spte)
{
	uint8_t *kpage;
	struct fte *evict_fte;
	struct fte *new_fte;
	bool success;

	spte->can_evict = false;
	if(spte->allocated)
	{
		return true;
	}
	lock_acquire(&frame_lock);
	kpage = get_frame(spte->flag);

	ASSERT(kpage != NULL);
	read_from_block(kpage, spte->disk_index);
	block_reset(spte->disk_index);

	success = install_page(spte->vaddr, kpage, spte->writable);
	if(!success)
	{
		palloc_free_page(kpage);
		lock_release(&frame_lock);
		return success;
	}

	new_fte = malloc(sizeof (struct fte));
	new_fte->owner = thread_current();
	new_fte->frame = kpage;
	new_fte->spte = spte;
	
	list_push_back(&frame_table, &new_fte->ft_elem);
	spte->allocated = true;	
	lock_release(&frame_lock);
	return true;
}

struct fte *fte_to_evict()
{
	struct fte *e;
	struct list_elem *it;
	it = list_begin(&frame_table);
	for(unsigned i = 0; i < 2 * (list_size(&frame_table)); i++)
	{
		e = list_entry(it, struct fte, ft_elem);
		if(e->spte->can_evict)
		{
			if(pagedir_is_accessed(e->owner->pagedir, e->spte->vaddr))
			{
				pagedir_set_accessed(e->owner->pagedir, e->spte->vaddr, false);
			}
			else
			{
				return e;
			}
		}
		it = list_next(it);
		if(it == list_end(&frame_table))
		{
			it = list_begin(&frame_table);
		}
	}
	printf("not found!\n");
	lock_release(&frame_lock);
	return NULL;
}

void *get_frame(enum palloc_flags flag)
{
	void *kpage;
	struct fte *evict_fte;
	kpage = palloc_get_page(PAL_USER | flag);
	if(kpage == NULL)
	{
		evict_fte = fte_to_evict();
		if(!evict(evict_fte))
		{
			printf("Eviction failed in load_sup_pte\n");
			return NULL;
		}
		kpage = palloc_get_page(PAL_USER | flag);
		if(kpage == NULL)
		{
			printf("Allocation after eviction failed in load_sup_pte\n");
			return NULL;
		}
	}
	return kpage;
}

struct fte *fte_search(void *vaddr)
{
	struct list_elem *e;
	struct fte *found_fte;
	for(e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
	{
		found_fte = list_entry(e, struct fte, ft_elem);
		if(found_fte->spte->vaddr == vaddr)
			return found_fte;
	}
	return NULL;
}
