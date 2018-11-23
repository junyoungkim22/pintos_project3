#include <bitmap.h>
#include "devices/block.h"

struct block *swap_block;
struct bitmap *sector_bitmap;

void read_from_block(void *frame, int index);
void swap_init();
