// BANNERSTART
// - Copyright 2006-2008, Galois, Inc.
// - This software is distributed under a standard, three-clause BSD license.
// - Please see the file LICENSE, distributed with this software, for specific
// - terms and conditions.
// Author: Adam Wick <awick@galois.com>
// BANNEREND
#include <Rts.h>
#include "GetTime.h"
#include "sm/OSMem.h"
#include "arch.h"
#include "mm.h"
#include "mman.h"
#include "stdio.h"

W_ getPageSize(void)
{
  return 4096;
}

W_ getPageFaults(void)
{
  return 0;
}

void setExecutable( void    *p    __attribute__((unused)),
                    lnat     len  __attribute__((unused)),
                    rtsBool  exec __attribute((unused))    )
{
  /* Not feasible on the x86 in 32-bit mode without messing with ugly
   * segmentation register stuff. */
  return;
}

/******************************************************************************/

static void *next_request = (void*)MBLOCK_SIZE;

void osMemInit(void)
{
  /* Nothing to do */ 
}

void *osGetMBlocks(nat n)
{
  void *start_attempt = next_request;
  size_t size = n * MBLOCK_SIZE;

  assert( ((uintptr_t)start_attempt % MBLOCK_SIZE) == 0);
  do {
    if( claim_vspace(next_request, size) ) {
      void *retval = next_request;
      back_pages(retval, (void*)((unsigned long)retval + size),
	         PROT_READ | PROT_WRITE );
      next_request = (void*)((unsigned long)next_request + size);
      return retval;
    }
    next_request = (void*)((unsigned long)next_request + MBLOCK_SIZE);
  } while(next_request != start_attempt);

  /* EEEK! We couldn't find memory to allocate! */
  printf("osGetMBlocks failing!\n");
  return NULL;
}

void osFreeMBlocks(char *addr, nat n)
{
  size_t size = n * MBLOCK_SIZE;
  void *start = (void*)addr;
  void *end   = (void*)((unsigned long)addr + size);

  unback_pages(start, end, 1);
  disclaim_vspace(start, end);
}

void osReleaseFreeMemory(void)
{
  /* not sure what the semantics of this are, but the fact that there's */
  /* nothing to be done for the POSIX implementation suggests that      */
  /* we're good doing nothing.                                          */
}

void osFreeAllMBlocks(void)
{
  /* Nothing really to do, this container is about to be destroyed, and
   * the shared library concern mentioned in the posix tree and bug 
   * report doesn't really matter */
}

