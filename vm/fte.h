#include<list.h>
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"

struct list frame_table;
struct list_elem *clock_pointer;

struct fte
{
	void *frame;
	struct thread *owner;
	struct sup_pte *spte;
	struct list_elem ft_elem;
};

uint8_t *allocate_frame(void *vaddr, enum palloc_flags flag, bool writable);

bool evict(struct fte*);
bool load_sup_pte(struct sup_pte*);
struct fte *fte_to_evict(void);
struct fte *clock_next_fte(void);
