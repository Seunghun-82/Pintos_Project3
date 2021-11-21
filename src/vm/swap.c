#include "vm/swap.h"

void swap_init()
{
    swap_block = block_get_role(BLOCK_SWAP);
    block_size(swap_block);
    swap_bitmap = bitmap_create(block_size(swap_block) / 8);
    bitmap_set_all(swap_bitmap, 0);
    lock_init(&swap_lock);

    return;
}

void swap_in(size_t used_index, void* kaddr)
{
    int i = 0;
    
    lock_acquire(&swap_lock);
    
    if(bitmap_test(swap_bitmap, used_index) == 0)
    {
        lock_release(&swap_lock);
        return;
    }

    for(i = 0; i < 8; i++)
    {
        block_read(swap_block, used_index * 8 + i, kaddr + i * BLOCK_SECTOR_SIZE);
    }
    bitmap_set(swap_bitmap, used_index, 0);

    lock_release(&swap_lock);
    return;
}

size_t swap_out(void* kaddr)
{
    lock_acquire(&swap_lock);
    int i;
    int index = bitmap_scan_and_flip(swap_bitmap, 0, 1, 0);
    if(index == BITMAP_ERROR)
    {
        lock_release(&swap_lock);
        return index;
    }

    for(i = 0; i < 8; i++)
    {
        block_write(swap_block, index * 8 + i, kaddr + i * BLOCK_SECTOR_SIZE);
    }

    lock_release(&swap_lock);
    return index;
}