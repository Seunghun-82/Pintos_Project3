#ifndef VM_PAGE_HEADER
#define VM_PAGE_HEADER

#include "lib/kernel/hash.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "lib/kernel/list.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "userprog/syscall.h"
#include "vm/swap.h"

struct list lru_list;
struct lock lru_lock;
struct page* lru_clock;

#define VM_BIN 0
#define VM_FILE 1
#define VM_ANON 2
#define VM_FRAME 3

struct vm_entry{
    uint8_t type; 
    void* vaddr;
    bool writable; 
    bool is_loaded; 
    struct file* file;

    struct list_elem mmap_elem;
    size_t offset;
    size_t read_bytes;
    size_t zero_bytes;

    size_t swap_slot; 

    struct hash_elem hash_elem; 
};

struct mmap_file{
    int mapid;
    struct file* file;
    struct list_elem elem;
    struct list vme_list;
};

struct page {
    void *kaddr;
    struct vm_entry*vme;
    struct thread *thread;
    struct list_elem lru;
};

void vm_init (struct hash *vm);
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux);
unsigned page_hash (const struct hash_elem *p_, void *aux);

bool insert_vme (struct hash *vm, struct vm_entry *vme);
bool delete_vme (struct hash *vm, struct vm_entry *vme);
struct vm_entry *find_vme (void *vaddr);
void vm_destroy(struct hash* vm);
void vm_destroy_func(struct hash_elem *e, void *aux);

void lru_list_init(void);
void add_page_to_lru_list(struct page* page);
void del_page_from_lru_list(struct page* page);
struct page* alloc_page(enum palloc_flags flags);
void free_page(void *kaddr);
struct list_elem* get_next_lru_clock();
// void try_to_free_pages (void* kaddr, enum palloc_flags flags);
void try_to_free_pages(void);

#endif