#include "vm/swap.h"

void swap_init(void)
{
	swap_block = block_get_role(BLOCK_SWAP);
	if(swap_block == NULL)
	{	
		sector_bitmap = bitmap_create(0);	
		return;
	}
	sector_bitmap = bitmap_create(block_size(swap_block));	
}
