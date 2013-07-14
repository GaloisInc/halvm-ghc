// from mini-os
/* 
 ****************************************************************************
 * (C) 2005 - Grzegorz Milos - Intel Reseach Cambridge
 ****************************************************************************
 *
 *        File: traps.h
 *      Author: Grzegorz Milos (gm281@cam.ac.uk)
 *              
 *        Date: Jun 2005
 * 
 * Environment: Xen Minimal OS
 * Description: Deals with traps
 *
 ****************************************************************************
 */

#ifndef _TRAPS_H_
#define _TRAPS_H_

#ifdef __i386__
struct pt_regs {
	long ebx;
	long ecx;
	long edx;
	long esi;
	long edi;
	long ebp;
	long eax;
	int  xds;
	int  xes;
	long orig_eax;
	long eip;
	int  xcs;
	long eflags;
	long esp;
	int  xss;
};
#elif __x86_64__
struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
/* arguments: non interrupts/non tracing syscalls only save upto here*/
 	unsigned long r11;
	unsigned long r10;	
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long orig_rax;
/* end of arguments */ 	
/* cpu exception frame or undefined */
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags; 
	unsigned long rsp; 
	unsigned long ss;
/* top of stack page */ 
};
#endif

void init_traps(void);
void dump_fpu_information(void);
void do_divide_error(struct pt_regs *, unsigned long) __attribute((noreturn));
void do_int3(struct pt_regs *, unsigned long) __attribute((noreturn));
void do_overflow(struct pt_regs *, unsigned long) __attribute((noreturn));
void do_bounds(struct pt_regs *, unsigned long) __attribute((noreturn));
void do_invalid_op(struct pt_regs *, unsigned long) __attribute((noreturn));
void do_device_not_available(struct pt_regs *, unsigned long) __attribute((noreturn));
void do_coprocessor_segment_overrun(struct pt_regs *, unsigned long) __attribute((noreturn));
void do_invalid_TSS(struct pt_regs *, unsigned long) __attribute((noreturn));
void do_segment_not_present(struct pt_regs *, unsigned long) __attribute((noreturn));
void do_stack_segment(struct pt_regs *, unsigned long) __attribute((noreturn));
void do_alignment_check(struct pt_regs *, unsigned long) __attribute((noreturn));
void do_machine_check(struct pt_regs *, unsigned long) __attribute((noreturn));
void do_page_fault(struct pt_regs *, unsigned long) __attribute((noreturn));
void do_general_protection(struct pt_regs *, long) __attribute((noreturn));
void do_debug(struct pt_regs *) __attribute((noreturn));
void do_coprocessor_error(struct pt_regs *) __attribute((noreturn));
void simd_math_error(void *eip) __attribute((noreturn));
void do_simd_coprocessor_error(struct pt_regs * regs) __attribute((noreturn));
void do_spurious_interrupt_bug(struct pt_regs *) __attribute((noreturn));

#endif /* _TRAPS_H_ */
