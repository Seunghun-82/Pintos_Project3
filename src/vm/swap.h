#ifndef SWAP_HEADER
#define SWAP_HEADER
#include "lib/kernel/bitmap.h"
#include "devices/block.h"
#include "threads/synch.h"

struct block* swap_block;
struct bitmap* swap_bitmap;
struct lock swap_lock;

void swap_init();
void swap_in(size_t used_index, void* kaddr);
size_t swap_out(void* kaddr);

#endif