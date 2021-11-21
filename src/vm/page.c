#include "vm/page.h"


unsigned page_hash(const struct hash_elem *p_, void *aux)
{
    const struct vm_entry *p = hash_entry(p_, struct vm_entry, hash_elem);
    return hash_bytes(&p->vaddr, sizeof p->vaddr);
}

bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux)
{
    const struct vm_entry *a = hash_entry(a_, struct vm_entry, hash_elem);
    const struct vm_entry *b = hash_entry(b_, struct vm_entry, hash_elem);

    return a->vaddr < b->vaddr;
}

void vm_init(struct hash *vm_table)
{
    hash_init(vm_table, page_hash, page_less, NULL);
}

bool insert_vme(struct hash *vm_table, struct vm_entry *vme)
{
    if(hash_insert(vm_table, vme) == NULL)
        return true;

    return false;
}

bool delete_vme(struct hash *vm_table, struct vm_entry *vme)
{
    if(hash_delete(vm_table, vme) == NULL)
    {
        free(vme);
        return false;
    }
    else
    {
        free(vme);
        return true;
    }
}

struct vm_entry *find_vme(void *vaddr)
{
    struct vm_entry *temp = (struct vm_entry *)malloc(sizeof(struct vm_entry));
    temp->vaddr = pg_round_down(vaddr);

    struct hash_elem *e = hash_find(&(thread_current()->vm_table), &(temp->hash_elem));
    
    free(temp);

    if (e == NULL)
        return NULL;

    return hash_entry(e, struct vm_entry, hash_elem);
}

void vm_destroy(struct hash* vm)
{
    hash_destroy(vm, vm_destroy_func);
}

void vm_destroy_func(struct hash_elem *e, void *aux)
{
    struct thread* cur = thread_current();
    struct vm_entry* rm_vme = hash_entry(e, struct vm_entry, hash_elem);
    if(rm_vme ->is_loaded == true)
    {
        void* tmp = pagedir_get_page(cur->pagedir, rm_vme->vaddr);
        free_page(tmp);
        pagedir_clear_page(cur->pagedir, rm_vme->vaddr);
    } 
    free(rm_vme);
}

void lru_list_init(void)
{
    lru_clock = NULL;
    list_init(&lru_list);
    lock_init(&lru_lock);
}

void add_page_to_lru_list(struct page* page)
{
    if(page != NULL)
    {
        lock_acquire(&lru_lock);
        list_push_back(&lru_list, &page->lru);
        lock_release(&lru_lock);   
    }
}

void del_page_from_lru_list(struct page* page)
{
    if(page != NULL)
    {
        lock_acquire(&lru_lock);
        list_remove(&page->lru);
        lock_release(&lru_lock);    
    }
}

struct page* alloc_page(enum palloc_flags flags)
{
    // void* kaddr = palloc_get_page(flags);
    // if(kaddr == NULL)
    // {
    //     try_to_free_pages(kaddr, flags);
    // }

    // struct page* new_page = malloc(sizeof(struct page));
    // new_page->kaddr = kaddr;
    // new_page->thread = thread_current();
    // add_page_to_lru_list(new_page);

    // return new_page;

    struct page *new_page;
	void *kaddr;
	if((flags & PAL_USER) == 0)
		return NULL;
	/* allocate physical memory */
	kaddr = palloc_get_page(flags);
	/* if fail, free physical memory and retry physical memory allocate*/
	while(kaddr == NULL)
	{
		try_to_free_pages();
		kaddr = palloc_get_page(flags);
	}
	new_page = malloc(sizeof(struct page));
	if(new_page == NULL)
	{
		palloc_free_page(kaddr);
		return NULL;
	}
	/* initialize page */
	new_page->kaddr  = kaddr;
	new_page->thread = thread_current();
	/* insert page to lru list */
	add_page_to_lru_list(new_page);
	return new_page;

}

void free_page(void *kaddr)
{
    struct list_elem* e;
    for(e = list_begin(&lru_list); e != list_end(&lru_list); e = list_next(e))
    {
        struct page* check_page = list_entry(e, struct page, lru);
        if(check_page->kaddr == kaddr)
        {
            del_page_from_lru_list(check_page);
            palloc_free_page(kaddr);
            free(check_page);
            break;
        }
    }
}

struct list_elem* get_next_lru_clock(void)
{
//     if(lru_clock == NULL || list_end(&lru_list) == &lru_clock->lru)
//     {
//         lru_clock = list_entry(list_begin(&lru_list), struct page, lru);
//     }
//     else
//     {
//         lru_clock = list_entry(list_next(&lru_clock->lru), struct page, lru);
//     }
//   return lru_clock;
    struct list_elem *element;
	/* if lru_clock is NULL */
	if(lru_clock == NULL)
	{
		element = list_begin(&lru_list);
		/* if lru_list is not empty list, return the first of list */
		if(element != list_end(&lru_list))
		{
			lru_clock = list_entry(element, struct page, lru);
			return element;
		}
		else
		{
			return NULL;
		}
	}
	element = list_next(&lru_clock->lru);
	/* if lru_clock page is final page of lru_list */
	if(element == list_end(&lru_list))
	{
		/* if lru_list has only one page */
		if(&lru_clock->lru == list_begin(&lru_list))
		{
			return NULL;
		}
		else
		{
			/* lru_list has more than one page, lru_clock points list begin page */
			element = list_begin(&lru_list);
		}
	}
	lru_clock = list_entry(element, struct page, lru);
	return element;

}

void try_to_free_pages (void)
{
    // while(kaddr == NULL)
    // {
    //     lock_acquire(&lru_lock);

    //     if(list_empty(&lru_list))
    //     {
    //         lock_release(&lru_lock);
    //         palloc_get_page(flags);
    //     }
        
    //     struct page* lru_clock = list_begin(&lru_list);

    //     while(1)
    //     {
    //         if(pagedir_is_accessed(lru_clock->thread->pagedir, lru_clock->vme->vaddr) == false)
    //             break;
    //         else
    //             pagedir_set_accessed(lru_clock->thread->pagedir, lru_clock->vme->vaddr, false);

    //         get_next_lru_clock(lru_clock);
    //     }

    //     if(pagedir_is_dirty(lru_clock->thread->pagedir, lru_clock->vme->vaddr) || lru_clock->vme->type == VM_ANON)
    //     {
    //         if(lru_clock->vme->type == VM_FILE)
    //         {
    //         lock_acquire(&file_lock);
    //         file_write_at(lru_clock->vme->file, lru_clock->kaddr, lru_clock->vme->read_bytes, lru_clock->vme->offset);
    //         lock_release(&file_lock);
    //         }
    //         else
    //         {
    //             lru_clock->vme->type = VM_ANON;
    //             int return_val = swap_out(lru_clock->kaddr);
    //             lru_clock->vme->swap_slot = return_val;
    //         }
    //     }

    //     lru_clock->vme->is_loaded = false;
    //     del_page_from_lru_list(lru_clock);
    //     palloc_free_page(lru_clock->kaddr);
    //     pagedir_clear_page(thread_current()->pagedir, lru_clock->vme->vaddr);
    //     free(lru_clock);

    //     palloc_get_page(flags);
    //     lock_release(&lru_lock);
    // }
    
    // return;

struct thread *page_thread;
	struct list_elem *element;
	struct page *lru_page;
	lock_acquire(&lru_lock);
	if(list_empty(&lru_list) == true)
	{
		lock_release(&lru_lock);
		return;
	}
	while(true)
	{
		/* get next element */
		element = get_next_lru_clock();
		if(element == NULL){
			lock_release(&lru_lock);
			return;
		}
		lru_page = list_entry(element, struct page, lru);
		// if(lru_page->vme->pinned == true)
		// 	continue;
		page_thread = lru_page->thread;
		/* if page address is accessed, set accessed bit 0 and continue(it's not victim) */
		if(pagedir_is_accessed(page_thread->pagedir, lru_page->vme->vaddr))
		{
			pagedir_set_accessed(page_thread->pagedir, lru_page->vme->vaddr, false);
			continue;
		}
		/* if not accessed, it's victim */
		/* if page is dirty */
		if(pagedir_is_dirty(page_thread->pagedir, lru_page->vme->vaddr) || lru_page->vme->type == VM_ANON)
		{
			/* if vm_entry is mmap file, don't call swap out.*/
			if(lru_page->vme->type == VM_FILE)
			{
				lock_acquire(&file_lock);
				file_write_at(lru_page->vme->file, lru_page->kaddr ,lru_page->vme->read_bytes, lru_page->vme->offset);
				lock_release(&file_lock);
			}
			/* if not mmap_file, change type to ANON and call swap_out function */
			else
			{
				lru_page->vme->type = VM_ANON;
				lru_page->vme->swap_slot = swap_out(lru_page->kaddr);
 			}
		}
		lru_page->vme->is_loaded = false;
		pagedir_clear_page(page_thread->pagedir, lru_page->vme->vaddr);
		__free_page(lru_page);
		break;
	}
    lock_release(&lru_lock);
	return;

}

void __free_page(struct page *page)
{
	/* free physical memory */
	palloc_free_page(page->kaddr);
	/* delete page from lru_list */
	del_page_from_lru_list(page);
	free(page);
}