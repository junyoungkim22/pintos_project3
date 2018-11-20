#include<list.h>
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

struct list frame_table;

struct fte
{
	uint8_t *frame;
	struct thread *owner;
	struct list_elem ft_elem;
};

uint8_t *get_frame(uint8_t *vaddr, enum palloc_flags flag, bool writable);
