#include <bitmap.h>
#include "devices/block.h"

struct block *swap_block;
struct bitmap *sector_bitmap;

void swap_init();
