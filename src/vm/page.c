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

void vm_destroy()
{
    return;
}