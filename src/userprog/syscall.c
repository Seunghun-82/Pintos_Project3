#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include <filesys/filesys.h>
#include <devices/shutdown.h>


static void syscall_handler (struct intr_frame *);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  // printf("in the syscall handler : %d\n", *(int *)(f->esp));
  // printf ("system call! \n");

  check_useradd(f->esp, f->esp);
  unsigned int handling_num = *((unsigned int *)(f->esp));
  // unit32_t* arg = (unit32_t *)malloc(sizeof(unit32_t) * num_arg);

  // check_useradd(f->esp);
  // check_useradd(f->esp + (num_arg - 1) * 4);

  // copy_argument(f->esp, arg, num_arg);

  switch (handling_num)
  {
  case SYS_HALT:
    halt();
    break;
  case SYS_EXIT:
    check_useradd(f->esp + 4, f->esp);
    exit(*((int *)(f->esp + 4)));
    break;
  case SYS_EXEC:
    check_useradd(f->esp + 4, f->esp);
    f->eax = sys_exec(*(const char**)(f->esp + 4));
    break;
  case SYS_WAIT:
    check_useradd(f->esp + 4, f->esp);
    f->eax = sys_wait(*(int*)(f->esp + 4));
    break;
  case SYS_CREATE:
    check_useradd(f->esp + 4, f->esp);
    check_useradd(f->esp + 8, f->esp);
    f->eax = create((*(char **)(f->esp + 4)), *((unsigned int *)(f->esp + 8)));
    break;
  case SYS_REMOVE:    
    check_useradd(f->esp + 4, f->esp);
    check_valid_string((void *)f->esp + 4, f->esp);
    f->eax = remove(*(char **)(f->esp + 4));
    break;    
  case SYS_OPEN:
    check_useradd(f->esp + 4, f->esp);
    check_valid_string((void *)f->esp + 4, f->esp);
    f->eax = open(*(const char**)(f->esp + 4));
    break;    
  case SYS_FILESIZE:
    check_useradd(f->esp + 4, f->esp);
    f->eax = filesize(*(int *)(f->esp + 4));
    break;    
  case SYS_READ:
    check_useradd(f->esp + 4, f->esp);
    check_useradd(f->esp + 8, f->esp);
    check_useradd(f->esp + 12, f->esp);
    check_valid_buffer(f->esp + 8, *(unsigned *)(f->esp + 12), true, f->esp);
    f->eax = read(*(int*)(f->esp + 4), *(char **)(f->esp + 8), *(unsigned *)(f->esp + 12));
    break;
  case SYS_WRITE:
    check_useradd(f->esp + 4, f->esp);
    check_useradd(f->esp + 8, f->esp);
    check_useradd(f->esp + 12, f->esp);
    check_valid_buffer(f->esp + 8, *(unsigned *)(f->esp + 12), false, f->esp);
    f->eax = write(*(int*)(f->esp + 4), *(char **)(f->esp + 8), *(unsigned *)(f->esp + 12));
    break;
  case SYS_SEEK:
    check_useradd(f->esp + 4, f->esp);
    check_useradd(f->esp + 8, f->esp);
    seek(*(int*)(f->esp + 4), *(unsigned *)(f->esp + 8));
    break;
  case SYS_TELL:
    check_useradd(f->esp + 4, f->esp);
    f->eax = tell(*(int*)(f->esp + 4));
    break;    
  case SYS_CLOSE:
    check_useradd(f->esp + 4, f->esp);
    close(*(int*)(f->esp + 4));
    break;  
  case SYS_MMAP:
    check_useradd(f->esp + 4, f->esp);
    check_useradd(f->esp + 8, f->esp);
    f->eax = sys_mmap(*(int*)(f->esp+4), (void *)(f->esp + 8));
    break;
  case SYS_MUNMAP:
    check_useradd(f->esp + 4, f->esp);
    munmap(*(int*)(f->esp+4));
    break;  
  default:
    break;
  }

  // thread_exit ();
}

void check_valid_string(void* str, void *esp)
{
	char *check_str = (char *)str;
	check_useradd((void *)check_str, esp);
	/* check the all string's address */
	while(*check_str != 0)
	{
		check_str += 1;
		check_useradd(check_str, esp);
	}
}

void check_valid_buffer(void* buffer, unsigned size, bool to_write, void* esp)
{
  int i;
  for(i = 0; i < size; i++)
  {
    struct vm_entry* check = check_useradd(buffer + i, esp);
      if(check == NULL)
        exit(-1);

      if(check->writable == false && to_write == true)
        exit(-1);    
  }
}

struct vm_entry* check_useradd(void *addr, void *esp)
{
  if(!is_user_vaddr(addr) || addr < (void *)0x08048000)
    exit(-1);
  struct vm_entry* vme = find_vme(addr);
  if(vme == NULL)
  {
    if(addr >= 32)
    {
      if(expand_stack(addr) == false)
        exit(-1);
    }
    else
      exit(-1);
  }
  return vme;
}

struct thread *get_child_process (int pid)
{
  struct list_elem* e;
  struct thread* cur = thread_current();
  for(e = list_begin(&(cur->child_list)); e != list_end(&cur->child_list); e = list_next(e))
  {
    struct thread* check_thread = list_entry(e, struct thread, child_elem);
    if (pid == check_thread->tid)
      return check_thread;
  }

  return NULL;
}

void remove_child_process(struct thread *cp)
{
  list_remove (&(cp->child_elem));
}


void halt(void)
{
  shutdown_power_off();
}

void exit(int status)
{
  struct thread *t = thread_current();

  t->exit_status = status;

  printf("%s: exit(%d)\n", t->name, status);

  thread_exit();
}

int create(const char* file, unsigned int initial_size)
{
  if(file == NULL)
    exit(-1);
  // check_useradd(file);
  int result;
  result = filesys_create(file, initial_size);
  return result;
}

int remove(const char *file)
{
  if(file == NULL)
    exit(-1);
  // check_useradd(file);
  int result;
  result = filesys_remove(file);
  return result;
}

int sys_exec (const char *cmd_line)
{
  tid_t child_tid;
  // check_useradd(cmd_line);
  child_tid = process_execute(cmd_line);

  if (child_tid == -1)
    return -1;

  struct thread * child_thread = get_child_process (child_tid);
  // sema_down(&thread_current()->parent_thread->sema_load);

  return child_tid;

  // if (child_thread->exit_status == 0)
  //   return child_tid;
  // return -1;
}

int sys_wait (tid_t tid)
{
  return process_wait(tid);
}

int open (const char *file)
{
  if(file == NULL)
    return -1;
  lock_acquire(&file_lock);
  struct file* open_file = filesys_open(file);

  if(strcmp(file, thread_current()->name) == 0)
    file_deny_write(open_file);

  if (open_file == NULL)
  {
    lock_release(&file_lock);
    return -1;
  }
  int ret_val = process_add_file(open_file);
  lock_release(&file_lock);
  return ret_val;
}

int filesize (int fd)
{
  struct thread *curr = thread_current();
  if (curr->file_num < fd || fd < 0 || curr->file_descriptor[fd] == NULL)
    exit(-1);
  return file_length(curr->file_descriptor[fd]);
}

int read (int fd, void *buffer, unsigned size)
{
  lock_acquire(&file_lock);
  // check_useradd(buffer);
  struct thread *curr = thread_current();
  int ret_val;
  if (curr->file_num < fd || fd == 1 || fd < 0)
  {  
    lock_release(&file_lock);
    return -1;
  }

  if (fd == 0)
  {
    int i;
    for (i = 0; i < size; i++)
    {
      if(input_getc() == NULL)
        break;
    }
    lock_release(&file_lock);
    return i;
  }
  else
  {
    if(curr->file_descriptor[fd] == NULL)
    {
      lock_release(&file_lock);
      return -1;
    }
    if(filesize(fd) < size)
    {
      lock_release(&file_lock);
      return -1;
    }
    ret_val = file_read(curr->file_descriptor[fd], buffer, size);
  }
  lock_release(&file_lock);

  return ret_val;
}

int write(int fd, void *buffer, unsigned size)
{
  // check_useradd(buffer);
  struct thread *curr = thread_current();
  if (curr->file_num < fd || fd == 0 || fd < 0)
    return -1;

  lock_acquire(&file_lock);
  int result;
  if (fd == 1)
  {
    putbuf((const char*)buffer, size);
    result = size;
  }
  else
  {
    // if(thread_current()->file_descriptor[fd]->deny_write)

    if(curr->file_descriptor[fd] == NULL)
    {    
      lock_release(&file_lock);
      exit(-1);
    }
    result = file_write(curr->file_descriptor[fd], buffer, size);
  }

  lock_release(&file_lock);
  // lock_release(&file_lock);
  return result;
}

void seek(int fd, unsigned position)
{
  struct thread* curr = thread_current();
  if (curr->file_num < fd || fd < 0 || curr->file_descriptor[fd] == NULL)
    exit(-1);
  struct file *curr_file = thread_current()->file_descriptor[fd];
  file_seek(curr_file, position);
}

unsigned tell (int fd)
{
  struct thread* curr = thread_current();
  if (curr->file_num < fd || fd < 0 || curr->file_descriptor[fd] == NULL)
    exit(-1);
  struct file *curr_file = thread_current()->file_descriptor[fd];
  return file_tell(curr_file);
}

void close(int fd)
{
  close_file(fd);
}

int sys_mmap(int fd, void * addr)
{
  // if (is_kernel_vaddr(addr))
  //   exit(-1);

  if((uint32_t)addr%PGSIZE != 0 || addr == NULL)
	{
		return 1;
	}
  struct mmap_file* new_mmap = malloc(sizeof(struct mmap_file));
  if(new_mmap == NULL)
		return 2;

  if(fd == 0 || fd == 1)      // ! fd limit can be changed 0 or 2
    return 7;

  struct file* file_ = get_file(fd);
  if(file_ == NULL)
    return 4;
  lock_acquire(&file_lock);
  struct file* cur_file = file_reopen(file_);
  lock_release(&file_lock);
  if(cur_file == NULL)
    return 5;

  struct thread* cur = thread_current();
  list_init(&(new_mmap->vme_list));
  // new_mmap->mapid = cur->mmap_num;
  cur->mmap_num = cur->mmap_num + 1;
  new_mmap->file = cur_file;
  
  int file_size = file_length(cur_file);
  int i = 0;

  void *virtual_address = addr;
  int32_t offset = 0;
  size_t page_read_bytes;

  while(file_size > 0)
  {
    struct vm_entry* new_entry = malloc(sizeof(struct vm_entry));

    page_read_bytes = file_size < PGSIZE ? file_size : PGSIZE;

    new_entry->type = VM_FILE;
    // new_entry->vaddr = addr + PGSIZE * i;
    new_entry->vaddr = virtual_address;

    new_entry->writable = true;
    new_entry->is_loaded = false;

    new_entry->file = cur_file;
    // new_entry->offset = PGSIZE * i;
    new_entry->offset = offset;
    new_entry->read_bytes = page_read_bytes;
    new_entry->zero_bytes = PGSIZE - page_read_bytes;

    new_entry->swap_slot = 0;    

    if(insert_vme(&(cur->vm_table), new_entry) == false)      // ! Check free malloc needed
    {
      return 6;
    }
    list_push_back(&(new_mmap->vme_list), &(new_entry->mmap_elem));

    file_size = file_size - page_read_bytes;
    offset += page_read_bytes;
    virtual_address += PGSIZE;
    i++;
  }

  list_push_back(&(cur->mmap_list), &(new_mmap->elem));

  return 0;
}

void munmap(int map_id)
{
  struct thread* cur = thread_current();
  struct list_elem* e;
  for(e = list_begin(&cur->mmap_list); e != list_end(&cur->mmap_list); e = list_next(e))
  {
    struct mmap_file* check_mmap = list_entry(e, struct mmap_file, elem);
    if(check_mmap->mapid != map_id)
      continue;
    else
    {
      struct list_elem* vme_e, * next;
      for(vme_e = list_begin(&check_mmap->vme_list); vme_e != list_end(&check_mmap->vme_list); vme_e = next)   
      {
        struct vm_entry* rm_vme = list_entry(vme_e, struct vm_entry, mmap_elem);

        if(rm_vme ->is_loaded == true)
        {
          if(pagedir_is_dirty(cur->pagedir, rm_vme->vaddr))
          {
            lock_acquire(&file_lock);
            file_write_at(rm_vme->file, rm_vme->vaddr, rm_vme->read_bytes, rm_vme->offset);
            lock_release(&file_lock);
          }
          free_page(pagedir_get_page(cur->pagedir, rm_vme->vaddr));
          pagedir_clear_page(cur->pagedir, rm_vme->vaddr);
        }

        next = list_next(vme_e);
        list_remove(vme_e);
        delete_vme(&cur->vm_table, rm_vme);
      }

      list_remove(e);
      lock_acquire(&file_lock);
      file_close(check_mmap->file);
      lock_release(&file_lock);
      free(check_mmap);
      break;
    }
  }
}