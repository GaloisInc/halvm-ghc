#define __XEN__
#include "Rts.h"
#include "Schedule.h"
#include "RtsSignals.h"
#include "RtsUtils.h"
#include "signals.h"
#include <runtime_reqs.h>
#include <string.h>
#include <sys/mman.h>
#include <xen/xen.h>
#include <xen/event_channel.h>
#include <xen/sched.h>
#include "hypercalls.h"
#include <assert.h>
#include "locks.h"
#include "vcpu.h"
#include "time_rts.h"

static void force_hypervisor_callback(void);

#define local_vcpu_info         vcpu_local_info->other_info
#define vcpu_mask               (local_vcpu_info.evtchn_upcall_mask)
#define sync_swap               __sync_lock_test_and_set


/* ************************************************************************ */

#define MAX_EVTCHANS            ((sizeof(long) * 8) * (sizeof(long) * 8))
#define MAX_PENDING_HANDLERS    MAX_EVTCHANS

typedef struct signal_handler {
  void         (*c_handler)(int);
  StgStablePtr  haskell_handler;
} signal_handler_t;

static signal_handler_t   *signal_handlers;
static struct shared_info *shared_info;
static unsigned long      *ipi_mask;

#ifdef __x86_64__
static struct pda
{
    int irqcount;       /* offset 0 (used in x86_64.S) */
    char *irqstackptr;  /*        8 */
} cpu0_pda;
#endif

void init_signals(struct shared_info *sinfo)
{
  shared_info = sinfo;
  signal_handlers = calloc(MAX_EVTCHANS, sizeof(signal_handler_t));
  memset(shared_info->evtchn_mask, 0xFF, sizeof(shared_info->evtchn_mask));
  ipi_mask = calloc(sizeof(unsigned long) * 8, sizeof(unsigned long));
  memset(ipi_mask, 0, sizeof(unsigned long) * 8 * sizeof(unsigned long));
}

long bind_virq(uint32_t virq, uint32_t vcpu)
{
  evtchn_bind_virq_t arg = { .virq = virq, .vcpu = vcpu, .port = 0 };
  long res = HYPERCALL_event_channel_op(EVTCHNOP_bind_virq, &arg);
  return (res >= 0) ? arg.port : res;
}

long bind_pirq(uint32_t pirq, int will_share)
{
  evtchn_bind_pirq_t arg = { .pirq  = pirq,
                             .flags = will_share ? BIND_PIRQ__WILL_SHARE : 0,
                             .port  = 0 };
  long res = HYPERCALL_event_channel_op(EVTCHNOP_bind_pirq, &arg);
  return (res >= 0) ? arg.port : res;
}

long bind_ipi(uint32_t vcpu)
{
  evtchn_bind_ipi_t arg = { .vcpu = vcpu, .port = 0 };
  long res = HYPERCALL_event_channel_op(EVTCHNOP_bind_ipi, &arg);
  unsigned long bit;
  int offset;

  if(res < 0)
    return res;

  offset = arg.port / (sizeof(unsigned long) * 8);
  bit    = 1 << (arg.port % (sizeof(unsigned long) * 8));
  __sync_fetch_and_or( &(ipi_mask[offset]), bit);

  return arg.port;
}

void set_c_handler(uint32_t chan, void (handler)(int))
{
  assert(chan < MAX_EVTCHANS);
  (void)sync_swap(&(signal_handlers[chan].c_handler), handler);
  unmask_channel(chan);
}

void clear_c_handler(uint32_t chan)
{
  assert(chan < MAX_EVTCHANS);
  mask_channel(chan);
  (void)sync_swap(&(signal_handlers[chan].c_handler), NULL);
}

void set_haskell_handler(uint32_t chan, StgStablePtr handler)
{
  assert(chan < MAX_EVTCHANS);
  (void)sync_swap(&(signal_handlers[chan].haskell_handler), handler);
  unmask_channel(chan);
}

void clear_haskell_handler(uint32_t chan)
{
  assert(chan < MAX_EVTCHANS);
  mask_channel(chan);
  (void)sync_swap(&(signal_handlers[chan].haskell_handler), NULL);
}

void mask_channel(uint32_t chan)
{
  asm volatile("lock btsl %1, %0"
              : "=m"(shared_info->evtchn_mask)
              : "r"(chan) : "memory");
}

void unmask_channel(uint32_t chan)
{
  int was_set = 0;

  asm volatile("lock btrl %1, %0" 
              : "=m"(shared_info->evtchn_mask)
              : "r"(chan) : "memory");
  /* it appears that masking off a channel simply forbids the interrupt */
  /* from being sent to us, not from the event being set pending. so    */
  /* running this clears out any undelivered events before we unmask an */
  /* event. */
  asm volatile("btl %2,%1 ; sbbl %0,%0"
              : "=r"(was_set)
              : "m"(shared_info->evtchn_pending), "r"(chan));
  if(was_set) {
    asm volatile("lock btsl %k2, %1 ; sbbl %0, %0"
                : "=r"(was_set), "=m"(local_vcpu_info.evtchn_pending_sel)
                : "r"(chan / (sizeof(unsigned long) * 8)) : "memory");
    if(!was_set) {
      vcpu_local_info->other_info.evtchn_upcall_pending = 1;
      if(!vcpu_mask) force_hypervisor_callback();
    }
  }
}

static inline void clear_channel(uint32_t chan)
{
  asm volatile("lock btrl %1, %0"
              : "=m"(shared_info->evtchn_pending)
              : "r"(chan) : "memory");
}

long channel_send(uint32_t chan)
{
  return HYPERCALL_event_channel_op(EVTCHNOP_send, &chan);
}

long channel_alloc(uint32_t local, uint32_t remote)
{
  evtchn_alloc_unbound_t arg = { .dom = local, .remote_dom = remote, .port = 0};
  long res = HYPERCALL_event_channel_op(EVTCHNOP_alloc_unbound, &arg);
  return res ? res : arg.port;
}

long channel_bind(uint32_t rdom, uint32_t rport)
{
  evtchn_bind_interdomain_t arg = { .remote_dom = rdom, .remote_port = rport };
  long res = HYPERCALL_event_channel_op(EVTCHNOP_bind_interdomain, &arg);
  return res ? res : arg.local_port;
}

long channel_close(uint32_t chan)
{
  return HYPERCALL_event_channel_op(EVTCHNOP_close, &chan);
}

/* ************************************************************************ */

void initDefaultHandlers(void)
{
  /* nothing! */
}

void resetDefaultHandlers(void)
{
  /* nothing! */
}

/* ************************************************************************ */

static StgStablePtr  *pending_handler_buf  = NULL;
static unsigned int   next_pending_handler = 0;

int signals_pending(void)
{
  force_hypervisor_callback();
  return next_pending_handler;
}

#include "vmm.h"

void allow_signals(int allow)
{
#if defined(__x86_64__)
  asm volatile("movl %0,%%fs ; movl %0,%%gs" :: "r" (0));
  asm volatile("wrmsr" : : "c"(0xc0000101), /* MSR_GS_BASE */
                           "a"((uintptr_t)&cpu0_pda & 0xFFFFFFFF),
                           "d"((uintptr_t)&cpu0_pda >> 32));
  cpu0_pda.irqcount    = -1;
  cpu0_pda.irqstackptr = vcpu_local_info->irq_stack_top;
#endif
  __sync_lock_test_and_set(&vcpu_mask, !!!allow);
  asm volatile("" : : : "memory");
  if(allow && vcpu_local_info->other_info.evtchn_upcall_pending)
    force_hypervisor_callback();
}

void initUserSignals(void)
{
  pending_handler_buf  = calloc(MAX_PENDING_HANDLERS, sizeof(StgStablePtr));
  next_pending_handler = 0;
}

void awaitUserSignals(void)
{
  force_hypervisor_callback();
  while(!signals_pending() && sched_state == SCHED_RUNNING)
    runtime_block(10 * 60 * 1000); // 10 minutes
}

rtsBool anyUserHandlers(void)
{
  int i;

  for(i = 0; i < (int)MAX_EVTCHANS; i++)
    if(signal_handlers[i].haskell_handler) {
      return rtsTrue;
    }

  return rtsFalse;
}

void blockUserSignals(void)
{
  /* nothing to do */
}

void unblockUserSignals(void)
{
  /* nothing to do */
}

/* ************************************************************************ */

void markSignalHandlers(evac_fn evac __attribute__((unused)),
                        void *user __attribute__((unused)))
{
  /* nothing -- stable pointers should prevent GC */
}

void freeSignalHandlers(void)
{
  /* nothing */
}

void startSignalHandlers(Capability *cap)
{
  unsigned int i;

  sync_swap(&vcpu_mask, 1);
  for(i = 0; i < next_pending_handler; i++) {
    StgClosure *h = (StgClosure*)deRefStablePtr(pending_handler_buf[i]);
    scheduleThread(cap, createIOThread(cap,RtsFlags.GcFlags.initialStkSize,h));
  }
  next_pending_handler = 0;
  sync_swap(&vcpu_mask, 0);
}

/* ************************************************************************ */

#ifndef THREADED_RTS
static rtsBool wakeUpSleepingThreads(StgWord now)
{
  rtsBool retval = rtsFalse;

   /* wake up anyone that's sleeping */
  while((sleeping_queue != END_TSO_QUEUE) &&
        (sleeping_queue->block_info.target <= now))
  {
    StgTSO *tso      = sleeping_queue;
    retval           = rtsTrue;
    sleeping_queue   = tso->_link;
    tso->why_blocked = NotBlocked;
    tso->_link       = END_TSO_QUEUE;
    pushOnRunQueue(&MainCapability, tso);
  }

  return retval;
}

void awaitEvent(rtsBool wait)
{
  do {
    StgWord now = getDelayTarget(0);

    if(wakeUpSleepingThreads(now))
      return;

    /* if we're supposed to wait, try blocking for awhile */
    if(wait) {
      lnat block_time = ~0;

      if(sleeping_queue != END_TSO_QUEUE) {
        block_time  = sleeping_queue->block_info.target - now; /* in us */
        block_time /= 1000; /* us -> ms */
      }
      runtime_block(block_time);
    }

    if(signals_pending()) {
      startSignalHandlers(&MainCapability);
      return;
    }

    if(sched_state >= SCHED_INTERRUPTING)
      return;

    wakeUpSleepingThreads(getDelayTarget(0));
  } while(wait && (sched_state == SCHED_RUNNING)
               && emptyRunQueue(&MainCapability));
}
#endif

#define one_day   (1 * 24 * 60 * 60 * 1000)

void runtime_block(unsigned long milliseconds)
{
  if(!signals_pending()) {
    allow_signals(0);
    force_hypervisor_callback();
    if(!signals_pending()) {
      uint64_t now, until;

      milliseconds = (milliseconds > one_day) ? one_day : milliseconds;
      now = monotonic_clock();
      until = now + (milliseconds * 1000000UL);
      if(monotonic_clock() < until) {
        set_vcpu_timer(until);
        assert(HYPERCALL_sched_op(SCHEDOP_block, 0) >= 0);
        force_hypervisor_callback();
        now = monotonic_clock();
      } else allow_signals(1);
    } else allow_signals(1);
  }
}

int stg_sig_install(int sig, int spi, void *mask __attribute__((unused)))
{
  assert(sig == 2);
  return spi;
}

/* ************************************************************************ */

static void force_hypervisor_callback(void)
{
  uint8_t save;

  while(local_vcpu_info.evtchn_upcall_pending) {
    save = __sync_lock_test_and_set(&vcpu_mask, 1);
    do_hypervisor_callback(NULL);
    save = __sync_lock_test_and_set(&vcpu_mask, save);
  }
}

void do_hypervisor_callback(void *u __attribute__((unused)))
{
  unsigned long lev1, lev2;

  while( sync_swap(&local_vcpu_info.evtchn_upcall_pending, 0) ) {
    while( (lev1 = sync_swap(&local_vcpu_info.evtchn_pending_sel, 0)) ) {
      while(lev1) {
        unsigned long idx = __builtin_ffsl(lev1), ipi_filter;
        unsigned long *pending;

        assert(idx);
        idx = idx - 1; /* ffsl returns offset + 1 */
        lev1 = lev1 & ~(1UL << idx);
        ipi_filter = ipi_mask[idx] ^ vcpu_local_info->local_evt_bits[idx];
        pending = &(shared_info->evtchn_pending[idx]);
        while( (lev2 = __sync_fetch_and_and(pending, ipi_filter))) {
          lev2 = lev2 & ~ipi_filter;
          while(lev2) {
            unsigned long idx2 = __builtin_ffsl(lev2), chn;

            assert(idx2);
            idx2 = idx2 - 1;
            chn = (idx * sizeof(unsigned long) * 8) + idx2;
            lev2 = lev2 & ~(1UL << idx2);

            if(signal_handlers[chn].c_handler) {
              signal_handlers[chn].c_handler(chn);
            }

            if(signal_handlers[chn].haskell_handler) {
              assert(next_pending_handler < MAX_PENDING_HANDLERS);
              pending_handler_buf[next_pending_handler++] =
                signal_handlers[chn].haskell_handler;
            }
          }
        }
      }
    }
  }
}


