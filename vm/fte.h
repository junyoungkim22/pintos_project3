#include<list.h>
#include "threads/palloc.h"
#include "userprog/pagedir.h"

struct fte
{
	uint8_t *frame;
	struct thread *owner;
	struct list_elem ft_list_entry;
};
