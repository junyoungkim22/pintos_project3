#include "vm/swap.h"

void read_from_block(void *frame, size_t index)
{
	for(int i = 0; i < 8; i++)
	{
		block_read(swap_block, index + i, frame + (i * BLOCK_SECTOR_SIZE));
	}
}

void write_to_block(void *frame, size_t index)
{
	for(int i = 0; i < 8; i++)
	{
		block_write(swap_block, index + i, frame + (i * BLOCK_SECTOR_SIZE));
	}
}

void block_reset(size_t index)
{
	for(int i = 0; i < 8; i++)
	{
		bitmap_reset(sector_bitmap, index + i);
	}
}

void block_mark(size_t index)
{
	for(int i = 0; i < 8; i++)
	{
		bitmap_mark(sector_bitmap, index + i);
	}
}

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
