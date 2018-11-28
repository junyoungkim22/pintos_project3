#include<list.h>
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"

struct list frame_table;

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
bool load_mmap(struct sup_pte*);
struct fte *fte_to_evict(void);
struct fte* fte_search(void *vaddr);
void *get_frame(enum palloc_flags flag);
