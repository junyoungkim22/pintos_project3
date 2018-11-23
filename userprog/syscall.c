#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "lib/string.h"
#include "lib/kernel/list.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);
static bool is_valid_vaddr(const void *va, struct intr_frame *f);
void *get_arg(void *esp, int arg_num, struct intr_frame *f);
int allocate_fd(void);
bool fd_compare(const struct list_elem *e1, const struct list_elem *e2, void *aux);
struct open_file *find_open_file(int fd);
bool string_valid_vaddr(char *s, struct intr_frame *f);
void allow_eviction(void *s, size_t size);

void
allow_eviction(void *s, size_t size)
{
	for(int i = 0; i < size; i++)
	{
		get_sup_pte(s + i)->can_evict = true;
	}
	get_sup_pte(s + size)->can_evict = true;
}

bool
string_valid_vaddr(char *s, struct intr_frame *f)
{
	char *it;
	it = s;
	while(1)
	{
		if(!is_valid_vaddr(it, f))
		{
			return false;
		}
		if(*it == NULL)
		{
			return true;
		}
		it++;
	}
}

void
syscall_init (void) 
{
	lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
	int syscall_num;
	int fd;
	char *buffer;
	unsigned size;
	bool success;
	char *name;
	struct file *file_addr;
	struct open_file *open_file;
	off_t new_pos;
	tid_t new_pid;  //1 to 1 mapping between tid and pid
	tid_t child_tid;

	syscall_num = (int) get_arg(f->esp, 0, f);
	switch(syscall_num)
	{
		case SYS_EXEC:	
			name = (char*) get_arg(f->esp, 1, f);
			if(!string_valid_vaddr(name, f))
				sys_exit(-1);
			lock_acquire(&filesys_lock);
			new_pid = process_execute(name);
			lock_release(&filesys_lock);
			sema_down(&thread_current()->start_info.start_sema);
			if(new_pid == TID_ERROR || !thread_current()->start_info.success)
			{
				f->eax = -1;
				//allow_eviction(name, strlen(name));
				break;
			}
			f->eax = new_pid;	
			//allow_eviction(name, strlen(name));
			break;
		case SYS_WAIT:	
			child_tid = (tid_t) get_arg(f->esp, 1, f);
			f->eax = process_wait(child_tid);
			break;
		case SYS_EXIT:
			sys_exit((int) get_arg(f->esp, 1, f));
			break;
		case SYS_CLOSE:
			fd = (int) get_arg(f->esp, 1, f);
			open_file = find_open_file(fd);
			if(open_file == NULL)
				break;
			list_remove(&open_file->open_file_elem);
			lock_acquire(&filesys_lock);
			file_close(open_file->file);
			lock_release(&filesys_lock);
			free(open_file);
			break;
		case SYS_OPEN:
			name = (char*) get_arg(f->esp, 1, f);
			if(!string_valid_vaddr(name, f))
				sys_exit(-1);
			lock_acquire(&filesys_lock);
			file_addr = filesys_open(name);
			if(file_addr == NULL)
			{
				f->eax = -1;
				lock_release(&filesys_lock);
				//allow_eviction(name, strlen(name));
				break;
			}
			lock_release(&filesys_lock);
			fd = allocate_fd();
			open_file = malloc(sizeof(struct open_file));
			open_file->fd = fd;
			open_file->file = file_addr;
			list_insert_ordered(&thread_current()->open_file_list, &open_file->open_file_elem, fd_compare, NULL);
			f->eax = fd;
			//allow_eviction(name, strlen(name));
			break;
		case SYS_READ:
			fd = (int) get_arg(f->esp, 1, f);
			buffer = (char*) get_arg(f->esp, 2, f);
			size = (off_t) get_arg(f->esp, 3, f);
			for(int i = 0; i < size; i++)
			{
				if(!is_valid_vaddr(buffer + i, f))
					sys_exit(-1);
			}
			/*
			if(!string_valid_vaddr(buffer, f))
				sys_exit(-1);
			*/
			if(!get_sup_pte(buffer)->writable)
				sys_exit(-1);
			if(fd == 0)
			{
				*buffer = (char) input_getc();
				f->eax = 1;
				//allow_eviction(buffer, size);
				break;
			}
			open_file = find_open_file(fd);
			if(open_file == NULL)
			{
				f->eax = -1;
				//allow_eviction(buffer, size);
				break;
			}
			lock_acquire(&filesys_lock);
			f->eax = file_read(open_file->file, buffer, size);
			lock_release(&filesys_lock);	
			//allow_eviction(buffer, size);
			break;
		case SYS_FILESIZE:	
			fd = (int) get_arg(f->esp, 1, f);
			open_file = find_open_file(fd);
			lock_acquire(&filesys_lock);
			f->eax = file_length(open_file->file);
			lock_release(&filesys_lock);
			break;
		case SYS_WRITE:
			fd = (int) get_arg(f->esp, 1, f);
			buffer = (char*) get_arg(f->esp, 2, f);
			size = (unsigned) get_arg(f->esp, 3, f);
			if(!string_valid_vaddr(buffer, f))
				sys_exit(-1);
			if(fd == 1)
			{
				putbuf(buffer, size);
				if(strlen(buffer) < size)
					f->eax = strlen(buffer);
				else
					f->eax = size;
				//allow_eviction(buffer, size);
				break;
			}
			open_file = find_open_file(fd);
			if(open_file == NULL)
			{
				f->eax = -1;
				//allow_eviction(buffer, size);
				break;
			}
			lock_acquire(&filesys_lock);
			f->eax = file_write(open_file->file, buffer, size);
			lock_release(&filesys_lock);
			//allow_eviction(buffer, size);
			break;
		case SYS_CREATE:
			name = (char*) get_arg(f->esp, 1, f);
			size = (unsigned) get_arg(f->esp, 2, f);
			if(!string_valid_vaddr(name, f))
				sys_exit(-1);
			lock_acquire(&filesys_lock);
			success = filesys_create(name, size);
			lock_release(&filesys_lock);
			f->eax = success;
			//allow_eviction(name, strlen(name));
			break;
		case SYS_REMOVE:
			name = (char*) get_arg(f->esp, 1, f);
			if(!string_valid_vaddr(name, f))
				sys_exit(-1);
			lock_acquire(&filesys_lock);
			success = filesys_remove(name);
			lock_release(&filesys_lock);
			f->eax = success;
			//allow_eviction(name, strlen(name));
			break;
		case SYS_SEEK:
			fd = (int) get_arg(f->esp, 1, f);
			new_pos = (off_t) get_arg(f->esp, 2, f);
			if(fd < 2)
				break;
			open_file = find_open_file(fd);
			if(open_file == NULL)
				break;
			lock_acquire(&filesys_lock);
			file_seek(open_file->file, new_pos);
			lock_release(&filesys_lock);	
			break;	
		case SYS_TELL:
			fd = (int) get_arg(f->esp, 1, f);
			if(fd < 2)
				break;
			open_file = find_open_file(fd);
			if(open_file == NULL)
				break;
			lock_acquire(&filesys_lock);
			f->eax = (unsigned) file_tell(open_file->file);
			lock_release(&filesys_lock);	
			break;		
		case SYS_HALT:
			shutdown_power_off();
			break;
	}
}

void sys_exit(int exit_status)
{
	thread_current()->exit_status = exit_status;
	char *save_ptr;
	char *file_name = strtok_r(thread_current()->name, " ", &save_ptr);
	printf("%s: exit(%d)\n", file_name, exit_status);
	thread_exit();
}

void *get_arg(void *esp, int arg_num, struct intr_frame *f)
{
	void *arg_addr = (esp + (4*arg_num));
	if(!is_valid_vaddr(arg_addr, f))
		sys_exit(-1);
	if(!is_valid_vaddr(arg_addr + 3, f))
		sys_exit(-1);
	return (void*) *((int*)arg_addr);
}

static bool is_valid_vaddr(const void *va, struct intr_frame *f)
{
	uint8_t *frame_addr = NULL;
	struct sup_pte *found_pte;
	if(!is_user_vaddr(va) || va < USER_ACCESS_LIMIT)
		return false;
	//if(pagedir_get_page(thread_current()->pagedir, va) == NULL)
	found_pte = get_sup_pte(va);
	//if(found_pte = get_sup_pte(va) == NULL)
	if(found_pte == NULL)
	{
		if((unsigned) va >= ((unsigned) f->esp) - 32)
		{
			void *new_upage_vaddr = pg_round_down(va);
			if(new_upage_vaddr < USER_STACK_LIMIT)
				return false;
			frame_addr = allocate_frame(new_upage_vaddr, NULL, true);
			if(frame_addr != NULL)
			{
				return true;
			}
		}
		return false;
	}
	//if(!found_pte->allocated)
	load_sup_pte(found_pte);
	//found_pte->can_evict = true;
	found_pte->access_time = timer_ticks();
	return true;
}

int
allocate_fd()
{
	struct list_elem *e;
	struct list *open_file_list = &thread_current()->open_file_list;
	struct open_file *of;
	int allo_fd = 2;
	for(e = list_begin(open_file_list); e != list_end(open_file_list); e = list_next(e))
	{
		of = list_entry(e, struct open_file, open_file_elem);
		if(of->fd == allo_fd)
			allo_fd++;
		else
			break;
	}
	return allo_fd;
}

struct 
open_file *find_open_file(int fd)
{
	struct list_elem *e;
	struct list *open_file_list = &thread_current()->open_file_list;
	struct open_file *of;
	for(e = list_begin(open_file_list); e != list_end(open_file_list); e = list_next(e))
	{
		of = list_entry(e, struct open_file, open_file_elem);
		if(of->fd == fd)
			return of;
	}
	return NULL;
}

bool fd_compare(const struct list_elem *e1, const struct list_elem *e2, void *aux)
{
	(void) aux;
	struct open_file *of1, *of2;
	of1 = list_entry(e1, struct open_file, open_file_elem);
	of2 = list_entry(e2, struct open_file, open_file_elem);
	return of1->fd < of2->fd;
}
