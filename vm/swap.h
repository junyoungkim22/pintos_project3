#include <bitmap.h>
#include "devices/block.h"

struct block *swap_block;
struct bitmap *sector_bitmap;

void read_from_block(void *frame, size_t index);
void write_to_block(void *frame, size_t index);
void block_reset(size_t index);
void block_mark(size_t index);
void swap_init(void);
