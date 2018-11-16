#include "fte.h"

bool get_frame(uint8_t *vaddr, enum palloc_flags flag, bool writable)
{
	uint8_t *kpage;
	bool success = false;
	struct fte *new_fte;
	kpage = palloc_get_page(PAL_USER | flag);
	if(kpage == NULL){
		return success; //did not implement eviction/allocation
	}
	success = install_page(vaddr, kpage, writable);
	if(!success)
	{
		palloc_free_page(kpage);
		return success;
	}

	return success;
}