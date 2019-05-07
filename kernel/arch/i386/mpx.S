/* This file is part of the lowest layer of the
 * MINIX kernel.  (The other part 
 * is "proc.c".)  The lowest layer does process 
 * switching and message handling. 
 * Furthermore it contains the assembler startup
 * code for Minix and the 32-bit 
 * interrupt handlers.  It cooperates with the 
 * code in "start.c" to set up a  
 * good environment for main(). 
 *
 * Kernel is entered either because of kernel-calls,
 * ipc-calls, interrupts or
 * exceptions. TSS is set so that the kernel stack
 * is loaded. The user context is
 * saved to the proc table and the handler of the 
 * event is called. Once the
 * handler is done, switch_to_user() function is 
 * called to pick a new process,
 * finish what needs to be done for the next process
 * to run, sets its context
 * and switch to userspace.
 *
 * For communication with the boot monitor at startup
 * time some constant 
 * data are compiled into the beginning of the text 
 * segment. This facilitates  
 * reading the data at the start of the boot process,
 * since only the first 
 * sector of the file needs to be read. 
 *
 * Some data storage is also allocated at the end of
 * this file. This data  
 * will be at the start of the data segment of the 
 * kernel and will be read 
 * and modified by the boot monitor before 
 * the kernel starts.
 */

#include "kernel/kernel.h" /* configures the kernel */

/* sections */

#include <machine/vm.h>
#include "kernel/kernel.h"
#include <minix/config.h>
#include <minix/const.h>
#include <minix/ipcconst.h>
#include <minix/com.h>
#include <machine/asm.h>
#include <machine/interrupt.h>
#include "archconst.h"
#include "kernel/const.h"
#include "kernel/proc.h"
#include "sconst.h"
#include <machine/multiboot.h>

#include "arch_proto.h" /* K_STACK_SIZE */

#ifdef CONFIG_SMP
#include "kernel/smp.h"
#endif

#include "htype.h"

/* Selected 386 tss offsets. */
#define TSS3_S_SP0	4

IMPORT(usermapped_offset)
IMPORT(copr_not_available_handler)
IMPORT(params_size)
IMPORT(params_offset)
IMPORT(switch_to_user)
IMPORT(multiboot_init)
/*Added by EKA*/
IMPORT(hardening_task)
IMPORT(hardening_exception_handler)
IMPORT(save_context)
IMPORT(h_step)
IMPORT(eax_s)
IMPORT(ebx_s)
IMPORT(ecx_s)
IMPORT(edx_s)
IMPORT(esi_s)
IMPORT(edi_s)
IMPORT(ebp_s)
IMPORT(esp_s)

IMPORT(eax_s1)
IMPORT(ebx_s1)
IMPORT(ecx_s1)
IMPORT(edx_s1)
IMPORT(esi_s1)
IMPORT(edi_s1)
IMPORT(ebp_s1)
IMPORT(esp_s1)

IMPORT(eax_s2)
IMPORT(ebx_s2)
IMPORT(ecx_s2)
IMPORT(edx_s2)
IMPORT(esi_s2)
IMPORT(edi_s2)
IMPORT(ebp_s2)
IMPORT(esp_s2)
IMPORT(origin_syscall)
IMPORT(h_pf_handle_by_k)
IMPORT(h_normal_pf)
/*End Added by EKA*/

.text
/*===================================================*/
/*		interrupt handlers	             */
/*  interrupt handlers for 386 32-bit protected mode */
/*===================================================*/
/* intr_handle(irq_handlers[irq]) */
#define PIC_IRQ_HANDLER(irq)	\
	push	$irq			        ;\
	call	_C_LABEL(irq_handle)		;\
	add	$4, %esp			;

/*===================================================*/
/*				hwint00 - 07         */
/*===================================================*/
/* Note this is a macro, it just 
 * looks like a subroutine. */

#define hwint_master(irq) \
	TEST_INT_IN_KERNEL(4, 0f)		;\
						\
	SAVE_PROCESS_CTX(0, KTS_INT_HARD)	;\
	push	%ebp				;\
	movl	$0, %ebp /* for stack trace */	;\
	call	_C_LABEL(context_stop)		;\
	add	$4, %esp			;\
	PIC_IRQ_HANDLER(irq)			;\
	movb	$END_OF_INT, %al		;\
	outb	$INT_CTL	                ;\
	jmp	_C_LABEL(switch_to_user)	;\
						\
0:						\
	pusha					;\
	call	_C_LABEL(context_stop_idle)	;\
	PIC_IRQ_HANDLER(irq)			;\
	movb	$END_OF_INT, %al		;\
	outb	$INT_CTL		        ;\
	CLEAR_IF(10*4(%esp))			;\
	popa					;\
	iret					;

/* Each of these entry points is an expansion 
 * of the hwint_master macro */
ENTRY(hwint00)
/* Interrupt routine for irq 0 (the clock). */
	hwint_master(0)

ENTRY(hwint01)
/* Interrupt routine for irq 1 (keyboard) */
	hwint_master(1)

ENTRY(hwint02)
/* Interrupt routine for irq 2 (cascade!) */
	hwint_master(2)

ENTRY(hwint03)
/* Interrupt routine for irq 3 (second serial) */
	hwint_master(3)

ENTRY(hwint04)
/* Interrupt routine for irq 4 (first serial) */
	hwint_master(4)

ENTRY(hwint05)
/* Interrupt routine for irq 5 (XT winchester) */
	hwint_master(5)

ENTRY(hwint06)
/* Interrupt routine for irq 6 (floppy) */
	hwint_master(6)

ENTRY(hwint07)
/* Interrupt routine for irq 7 (printer) */
	hwint_master(7)

/*==============================================*/
/*				hwint08 - 15	*/
/*==============================================*/
/* Note this is a macro, it just looks 
 * like a subroutine. */
#define hwint_slave(irq)	\
	TEST_INT_IN_KERNEL(4, 0f)		;\
						\
	SAVE_PROCESS_CTX(0, KTS_INT_HARD)	;\
	push	%ebp				;\
	movl	$0, %ebp	/* for stack trace */;\
	call	_C_LABEL(context_stop)		;\
	add	$4, %esp			;\
	PIC_IRQ_HANDLER(irq)			;\
	movb	$END_OF_INT, %al		;\
	outb	$INT_CTL		;\
	outb	$INT2_CTL		;\
	jmp	_C_LABEL(switch_to_user)	;\
						\
0:						\
	pusha					;\
	call	_C_LABEL(context_stop_idle)	;\
	PIC_IRQ_HANDLER(irq)			;\
	movb	$END_OF_INT, %al		;\
	outb	$INT_CTL	;\
	outb	$INT2_CTL		;\
	CLEAR_IF(10*4(%esp))			;\
	popa					;\
	iret					;

/* Each of these entry points is an expansion 
 * of the hwint_slave macro */
ENTRY(hwint08)
/* Interrupt routine for irq 8 (realtime clock) */
	hwint_slave(8)

ENTRY(hwint09)
/* Interrupt routine for irq 9 (irq 2 redirected) */
	hwint_slave(9)

ENTRY(hwint10)
/* Interrupt routine for irq 10 */
	hwint_slave(10)

ENTRY(hwint11)
/* Interrupt routine for irq 11 */
	hwint_slave(11)

ENTRY(hwint12)
/* Interrupt routine for irq 12 */
	hwint_slave(12)

ENTRY(hwint13)
/* Interrupt routine for irq 13 (FPU exception) */
	hwint_slave(13)

ENTRY(hwint14)
/* Interrupt routine for irq 14 (AT winchester) */
	hwint_slave(14)

ENTRY(hwint15)
/* Interrupt routine for irq 15 */
	hwint_slave(15)

/* differences with sysenter:
 *   - we have to find our own per-cpu stack
 *  (i.e. post-SYSCALL
 *     %esp is not configured)
 *   - we have to save the post-SYSRET %eip, 
 *   provided by the cpu
 *     in %ecx
 *   - the system call parameters are passed in %ecx,
 *    so we userland
 *     code that executes SYSCALL copies %ecx to %edx. 
 *     So the roles
 *     of %ecx and %edx are reversed
 *   - we can use %esi as a scratch register
 */
#define ipc_entry_syscall_percpu(cpu)		;\
ENTRY(ipc_entry_syscall_cpu ## cpu)		;\
	xchg	%ecx, %edx			;\
	mov	k_percpu_stacks+4*cpu, %esi	;\
	mov	(%esi), %ebp 			;\
	movl	$KTS_SYSCALL, P_KERN_TRAP_STYLE(%ebp) ;\
	xchg	%esp, %esi			;\
	jmp	syscall_sysenter_common

ipc_entry_syscall_percpu(0)
ipc_entry_syscall_percpu(1)
ipc_entry_syscall_percpu(2)
ipc_entry_syscall_percpu(3)
ipc_entry_syscall_percpu(4)
ipc_entry_syscall_percpu(5)
ipc_entry_syscall_percpu(6)
ipc_entry_syscall_percpu(7)

ENTRY(ipc_entry_sysenter)
    /* SYSENTER simply sets kernel segments, 
     * EIP to here, and ESP
     * to tss->sp0 (through MSR). so no 
     * automatic context saving is done.
     * interrupts are disabled.
     *
     * register usage:
     * edi: call type (IPCVEC, KERVEC)
     * ebx, eax, ecx: syscall params, set by userland
     * esi, edx: esp, eip to restore, set by userland
     *
     * no state is automatically saved; 
     * userland does all of that.
     */
    /* get proc saved by arch_finish_switch_to_user */
	mov	(%esp), %ebp 

	/* inform kernel we entered by sysenter
         * and should
	 * therefore exit through 
         * restore_user_context_sysenter
	 */
	movl	$KTS_SYSENTER, P_KERN_TRAP_STYLE(%ebp)
        	/* compensate for mapping difference */
	add	usermapped_offset, %edx

syscall_sysenter_common:
        /* esi is return esp */
	mov	%esi, SPREG(%ebp)
        /* edx is return eip */	
	mov	%edx, PCREG(%ebp)	

	/* save PSW */
	pushf
	pop	%edx
	mov	%edx, PSWREG(%ebp)

        /*Added by EKA hardening 1st run or 2nd run*/
        /**Save the general purpose registers*/
	mov %eax, eax_s
	mov %ebx, ebx_s
	mov %ecx, ecx_s
	mov %edx, edx_s
	mov %esi, esi_s
	mov %edi, edi_s
	mov %ebp, ebp_s
	mov %esp, esp_s
        /**record the origin of the trap**/
	mov $1  ,   %eax
	mov %eax, origin_syscall
	mov eax_s, %eax

        /**Test the step. 1st or 2nd and 
         * jump to the hardening handler**/
        cmpl $1, h_step
	jz  hardening_task_entry

	/*check  hardening task second run*/
	cmpl $2, h_step
	jz  hardening_task_entry

        /**reset the origin value**/
	mov $0  ,   %eax
	mov %eax, origin_syscall
	mov eax_s, %eax
        /* End added by EKA*/
        /**call the Minix normal SYS_ENTER Handler**/

ENTRY(cont_sys_call_entry)
	/* check for call type; do_ipc? */
	cmpl	$IPCVEC_UM, %edi
	jz	ipc_entry_common

	/* check for kernel trap */
	cmpl	$KERVEC_UM, %edi
	jz	kernel_call_entry_common

	/* unrecognized call number; 
         * restore user with error */
	movl	$-1, AXREG(%ebp)
	push	%ebp
        /* restore_user_context(%ebp); */	
	call	restore_user_context	

/*
 * IPC is only from a process to kernel
 */
ENTRY(ipc_entry_softint_orig)
	SAVE_PROCESS_CTX(0, KTS_INT_ORIG)
   /**Added by EKA Save the general purpose registers*/
	mov %ebx, ebx_s
	mov %ecx, ecx_s
	mov %edx, edx_s
	mov %esi, esi_s
	mov %edi, edi_s
	mov %ebp, ebp_s
	mov %esp, esp_s
	mov %eax, eax_s
        /**record the origin of the trap**/
	mov $2  ,   %eax
	mov %eax, origin_syscall
	mov eax_s, %eax

       /*check  hardening task first run*/
        /**Test the step. 1st or 2nd and jump
         * to the hardening handler**/
	cmpl	$1, h_step
	jz  hardening_task_entry

	/*check  hardening task second run*/
	cmpl $2, h_step
	jz  hardening_task_entry

        /**reset the origin value**/
	mov $0  ,   %eax
	mov %eax, origin_syscall
	mov eax_s, %eax
       /*End added by EKA*/
       /**call the Minix normal IPC_ORIGIN Handler**/
ENTRY(cont_sys_call_entry_2)
	jmp ipc_entry_common

ENTRY(ipc_entry_softint_um)
	SAVE_PROCESS_CTX(0, KTS_INT_UM)
        /*Added by EKA*/
        mov %ebx, ebx_s
	mov %ecx, ecx_s
	mov %edx, edx_s
	mov %esi, esi_s
	mov %edi, edi_s
	mov %ebp, ebp_s
	mov %esp, esp_s
	mov %eax, eax_s
	mov $3  ,   %eax
	mov %eax, origin_syscall
	mov eax_s, %eax
       /*check  hardening task first run*/
        /**Test the step. 1st or 2nd and jump 
       * to the hardening handler**/
        cmpl $1, h_step
	jz  hardening_task_entry

	/*check  hardening task second run*/
         /**Test the step. 1st or 2nd and jump 
         * to the hardening handler**/
	cmpl $2, h_step
	jz  hardening_task_entry

	mov $0  ,   %eax
	mov %eax, origin_syscall
	mov eax_s, %eax
     /*End added by EKA*/
     /**call the Minix normal KTS_INT_UM Handler**/
ENTRY(cont_sys_call_entry_3)
	jmp ipc_entry_common

ENTRY(ipc_entry_common)
	/* save the pointer to the current process */
	push	%ebp

	/*
	 * pass the syscall arguments from 
         * userspace to the handler.
	 * SAVE_PROCESS_CTX() does not clobber 
         * these registers, they are still
	 * set as the userspace have set them
	 */
	push	%ebx
	push	%eax
	push	%ecx

	/* stop user process cycles */
	push	%ebp
	/* for stack trace */
	movl	$0, %ebp
	call	_C_LABEL(context_stop)
	add	$4, %esp

	call	_C_LABEL(do_ipc)

	/* restore the current process pointer 
         * and save the return value */
	add	$3 * 4, %esp
	pop	%esi
	mov     %eax, AXREG(%esi)

	jmp	_C_LABEL(switch_to_user)


/*
 * kernel call is only from a process to kernel
 */
ENTRY(kernel_call_entry_orig)
	SAVE_PROCESS_CTX(0, KTS_INT_ORIG)
        /*added by EKA*/
        mov %ebx, ebx_s
	mov %ecx, ecx_s
	mov %edx, edx_s
	mov %esi, esi_s
	mov %edi, edi_s
	mov %ebp, ebp_s
	mov %esp, esp_s
	mov %eax, eax_s
	mov $4  ,   %eax
	mov %eax, origin_syscall
	mov eax_s, %eax
        /*check  hardening task first run*/
        /**Test the step. 1st or 2nd and jump 
         * to the hardening handler**/
        cmpl $1, h_step
	jz  hardening_task_entry

	/*check  hardening task second run*/
         /**Test the step. 1st or 2nd and jump 
          * to the hardening handler**/
	cmpl $2, h_step
	jz  hardening_task_entry

	mov $0  ,   %eax
	mov %eax, origin_syscall
	mov eax_s, %eax
        /*End added by EKA*/
    /**call the Minix normal KTS_INT_ORIG Handler**/
ENTRY(cont_sys_call_entry_4)
	jmp	kernel_call_entry_common

ENTRY(kernel_call_entry_um)
	SAVE_PROCESS_CTX(0, KTS_INT_UM)
        /*added by EKA*/
        mov %ebx, ebx_s
	mov %ecx, ecx_s
	mov %edx, edx_s
	mov %esi, esi_s
	mov %edi, edi_s
	mov %ebp, ebp_s
	mov %esp, esp_s
	mov %eax, eax_s
	mov $5  ,   %eax
	mov %eax, origin_syscall
	mov eax_s, %eax
        /*check  hardening task first run*/
        /**Test the step. 1st or 2nd and jump 
         * to the hardening handler**/
        cmpl $1, h_step
	jz  hardening_task_entry

	/*check  hardening task second run*/
         /**Test the step. 1st or 2nd and jump 
         * to the hardening handler**/
	cmpl $2, h_step
	jz  hardening_task_entry

	mov $0  ,   %eax
	mov %eax, origin_syscall
	mov eax_s, %eax
        /*End added by EKA*/
    /**call the Minix normal KTS_INT_UM Handler**/
ENTRY(cont_sys_call_entry_5)
	jmp	kernel_call_entry_common

ENTRY(kernel_call_entry_common)
	/* save the pointer to the current process */
	push	%ebp

	/*
	 * pass the syscall arguments from 
         * userspace to the handler.
	 * SAVE_PROCESS_CTX() does not clobber 
         * these registers, they are still
	 * set as the userspace have set them
	 */
	push	%eax

	/* stop user process cycles */
	push	%ebp
	/* for stack trace */
	movl	$0, %ebp
	call	_C_LABEL(context_stop)
	add	$4, %esp

	call	_C_LABEL(kernel_call)

	/* restore the current process pointer 
         * and save the return value */
	add	$8, %esp

	jmp	_C_LABEL(switch_to_user)
/* added by EKA*/
/** Call the hardening task**/
ENTRY(hardening_task_entry)
     call _C_LABEL(hardening_task)
/** Restore the resgisters and continue 
  * to the normal execption handlers**/
ENTRY(hardening_task_2_entry)
     movl eax_s, %eax
     movl ebx_s, %ebx
     movl ecx_s, %ecx
     movl edx_s, %edx
     movl esi_s, %esi
     movl edi_s, %edi
     movl ebp_s, %ebp
     movl esp_s, %esp

     cmpl $2, origin_syscall
     jz cont_sys_call_entry_2

     cmpl $3, origin_syscall
     jz cont_sys_call_entry_3

     cmpl $4, origin_syscall
     jz cont_sys_call_entry_4

     cmpl $5, origin_syscall
     jz cont_sys_call_entry_5

     jmp cont_sys_call_entry

/* An exception occur.
 *  Verify the nature of the exception
 ** -If it is a normal PF let the VM handle it
 ** -If it is a hardened PF let the kernel handle it**/

ENTRY(hardening_exception_entry)
     push	%esp  /* push the frame pointer
     * to the stack*/
     /* call the hardening exception handler*/
     call _C_LABEL(hardening_exception_handler) 
     add	$4, %esp
     /* It is normal page fault or retirement 
      * counter exception overflow
      * go to hardening_exception_task_entry
      * hardening_exception_handler 
      * had set h_stop_pe = 1  */
     cmpl $1, h_stop_pe 
     /* The kernel should handle the PF*/
     jz  hardening_exception_task_entry
     /* continue to the normal exception handling*/
     jmp cont_exception_handling 

     /* call the hardening task with handle 
      * hardening activities */
ENTRY(hardening_exception_task_entry)
     call _C_LABEL(hardening_task) 
     /* go to the normal exception handling */
     jmp cont_exception_handling 
/*End added by EKA*/

.balign 16
/*
 * called by the exception interrupt vectors.
 * If the exception does not push
 * errorcode, we assume that the vector 
 * handler pushed 0 instead. Next pushed
 * thing is the vector number. From this 
 * point on we can continue as if every
 * exception pushes an error code
 */
 /** Exception entry from kernel**/
exception_entry:
	/*
	 * check if it is a nested trap by 
         * comparing the saved code segment
	 * descriptor with the kernel CS first
	 */
	TEST_INT_IN_KERNEL(12, exception_entry_nested)

exception_entry_from_user:
        /* added by EKA check  hardening 
         * task first or second run*/
	cmpl $1, h_step
        jz save_reg_1
        cmpl $2, h_step
        jz save_reg_2
       
ENTRY(save_ctx_1)
        /* end EKA addition*/
	SAVE_PROCESS_CTX(8, KTS_INT_HARD)
        /* remember where interrupt come from*/
        mov $6  ,   %eax
	mov %eax, origin_syscall 
       /* save the esp that contains the frame pointer*/
        mov %esp, esp_s  
        /* save the ebp that points to the proc struct*/
        mov %ebp, ebp_s  
        /* handle the page fault in 
         * hardening manner if it is 1st run*/
        /*check  hardening task first run*/
        cmpl $1, h_step   
	jz  hardening_exception_entry
	/* handle the page fault in hardening 
         * manner if it is 2nd run*/
        /*check  hardening task second run*/
	cmpl $2, h_step 
	jz  hardening_exception_entry
        
ENTRY(cont_exception_handling) 
        /* continue the normal exception handling 
         * restore esp and ebp */
        movl esp_s, %esp
        movl ebp_s, %ebp
/** end EKA addition**/
	/* stop user process cycles */
	push	%ebp
	/* for stack trace clear %ebp */
	movl	$0, %ebp
	call	_C_LABEL(context_stop)
	add	$4, %esp

	/*
	 * push a pointer to the interrupt 
         * state pushed by the cpu and the
	 * vector number pushed by the vector 
         * handler just before calling
	 * exception_entry and call the exception 
         * handler.
	 */
	push	%esp
	push	$0 /* it's not a nested exception */
	call 	_C_LABEL(exception_handler)

	jmp	_C_LABEL(switch_to_user)

exception_entry_nested:

	pusha
	mov	%esp, %eax
	add	$(8 * 4), %eax
	push	%eax
	pushl	$1	/* it's a nested exception */
	call	_C_LABEL(exception_handler)
	add	$8, %esp
	popa

	/* clear the error code and 
         * the exception number */
	add	$8, %esp
	/* resume execution at the 
         * point of exception */
	iret

ENTRY(save_reg_1)
        /**Save the general purpose registers*/
        mov %eax, eax_s1
	mov %ebx, ebx_s1
	mov %ecx, ecx_s1
	mov %edx, edx_s1
	mov %esi, esi_s1
	mov %edi, edi_s1
	mov %ebp, ebp_s1
	mov %esp, esp_s1
        jmp save_ctx_1

ENTRY(save_reg_2)
        /**Save the general purpose registers*/
        mov %eax, eax_s2
	mov %ebx, ebx_s2
	mov %ecx, ecx_s2
	mov %edx, edx_s2
	mov %esi, esi_s2
	mov %edi, edi_s2
	mov %ebp, ebp_s2
	mov %esp, esp_s2
        jmp save_ctx_1

ENTRY(restore_user_context_sysenter)
	/* return to userspace using sysexit.
	 * most of the context saving the userspace process is
	 * responsible for, we just have to take care of the right EIP
	 * and ESP restoring here to resume execution, and set EAX and
	 * EBX to the saved status values.
	 */
	mov	4(%esp), %ebp		/* retrieve proc ptr arg */
	movw	$USER_DS_SELECTOR, %ax
	movw	%ax, %ds
	mov	PCREG(%ebp), %edx	/* sysexit restores EIP using EDX */
	mov	SPREG(%ebp), %ecx	/* sysexit restores ESP using ECX */
	mov	AXREG(%ebp), %eax	/* trap return value */
	mov	BXREG(%ebp), %ebx	/* secondary return value */

        /* restore PSW */
        movl    PSWREG(%ebp), %edi      /* load desired PSW to EDI */
        push    %edi
        popf

	sti				/* enable interrupts */
	sysexit				/* jump to EIP in user */

ENTRY(restore_user_context_syscall)
	/* return to userspace using sysret.
	 * the procedure is very similar to sysexit; it requires
	 * manual %esp restoring, new EIP in ECX, does not require
	 * enabling interrupts, and of course sysret instead of sysexit.
	 */
	mov	4(%esp), %ebp		/* retrieve proc ptr arg */

        /* restore PSW (before we switch to user stack!) */
        movl    PSWREG(%ebp), %edi      /* load desired PSW to EDI */
        push    %edi
        popf

	mov	PCREG(%ebp), %ecx	/* sysret restores EIP using ECX */
	mov	SPREG(%ebp), %esp	/* restore ESP directly */
	mov	AXREG(%ebp), %eax	/* trap return value */
	mov	BXREG(%ebp), %ebx	/* secondary return value */

	sysret				/* jump to EIP in user */

ENTRY(restore_user_context_int)
	mov	4(%esp), %ebp	/* will assume P_STACKBASE == 0 */

	/* reconstruct the stack for iret */
	push	$USER_DS_SELECTOR	/* ss */
	movl	SPREG(%ebp), %eax
	push	%eax
	movl	PSWREG(%ebp), %eax
	push	%eax
	push	$USER_CS_SELECTOR	/* cs */
	movl	PCREG(%ebp), %eax
	push	%eax

	/* Restore segments as the user should see them. */
	movw	$USER_DS_SELECTOR, %si
        movw    %si, %ds
        movw    %si, %es
        movw    %si, %fs
        movw    %si, %gs

	/* Same for general-purpose registers. */
	RESTORE_GP_REGS(%ebp)

	movl	BPREG(%ebp), %ebp

	iret	/* continue process */

/*===========================================================================*/
/*				exception handlers			     */
/*===========================================================================*/

#define EXCEPTION_ERR_CODE(vector)	\
	push	$vector			;\
	jmp	exception_entry

#define EXCEPTION_NO_ERR_CODE(vector)	\
	pushl	$0		;\
	EXCEPTION_ERR_CODE(vector)

LABEL(divide_error)
	EXCEPTION_NO_ERR_CODE(DIVIDE_VECTOR)

LABEL(single_step_exception)
	EXCEPTION_NO_ERR_CODE(DEBUG_VECTOR)

LABEL(nmi)
	EXCEPTION_NO_ERR_CODE(NMI_VECTOR)


LABEL(nmi_2)
#ifndef USE_WATCHDOG
	EXCEPTION_NO_ERR_CODE(NMI_VECTOR)
#else
	/*
	 * We have to be very careful as this interrupt can occur anytime. On
	 * the other hand, if it interrupts a user process, we will resume the
	 * same process which makes things a little simpler. We know that we are
	 * already on kernel stack whenever it happened and we can be
	 * conservative and save everything as we don't need to be extremely
	 * efficient as the interrupt is infrequent and some overhead is already
	 * expected.
	 */

	/*
	 * save the important registers. We don't save %cs and %ss and they are
	 * saved and restored by CPU
	 */
	pushw	%ds
	pushw	%es
	pushw	%fs
	pushw	%gs
	pusha

	/*
	 * We cannot be sure about the state of the kernel segment register,
	 * however, we always set %ds and %es to the same as %ss
	 */
	mov	%ss, %si
	mov	%si, %ds
	mov	%si, %es

	push	%esp
	call	_C_LABEL(nmi_watchdog_handler)
	add	$4, %esp

	/* restore all the important registers as they were before the trap */
	popa
	popw	%gs
	popw	%fs
	popw	%es
	popw	%ds

	iret
#endif

LABEL(breakpoint_exception)
	EXCEPTION_NO_ERR_CODE(BREAKPOINT_VECTOR)

LABEL(overflow)
	EXCEPTION_NO_ERR_CODE(OVERFLOW_VECTOR)

LABEL(bounds_check)
	EXCEPTION_NO_ERR_CODE(BOUNDS_VECTOR)

LABEL(inval_opcode)
	EXCEPTION_NO_ERR_CODE(INVAL_OP_VECTOR)

LABEL(copr_not_available)
	TEST_INT_IN_KERNEL(4, copr_not_available_in_kernel)
	cld			/* set direction flag to a known value */
	SAVE_PROCESS_CTX(0, KTS_INT_HARD)
	/* stop user process cycles */
	push	%ebp
	mov	$0, %ebp
	call	_C_LABEL(context_stop)
	call	_C_LABEL(copr_not_available_handler)
	/* reached upon failure only */
	jmp	_C_LABEL(switch_to_user)

copr_not_available_in_kernel:
	pushl	$0
	pushl	$COPROC_NOT_VECTOR
	jmp	exception_entry_nested

LABEL(double_fault)
	EXCEPTION_ERR_CODE(DOUBLE_FAULT_VECTOR)

LABEL(copr_seg_overrun)
	EXCEPTION_NO_ERR_CODE(COPROC_SEG_VECTOR)

LABEL(inval_tss)
	EXCEPTION_ERR_CODE(INVAL_TSS_VECTOR)

LABEL(segment_not_present)
	EXCEPTION_ERR_CODE(SEG_NOT_VECTOR)

LABEL(stack_exception)
	EXCEPTION_ERR_CODE(STACK_FAULT_VECTOR)

LABEL(general_protection)
	EXCEPTION_ERR_CODE(PROTECTION_VECTOR)

LABEL(page_fault)
	EXCEPTION_ERR_CODE(PAGE_FAULT_VECTOR)

LABEL(copr_error)
	EXCEPTION_NO_ERR_CODE(COPROC_ERR_VECTOR)

LABEL(alignment_check)
	EXCEPTION_NO_ERR_CODE(ALIGNMENT_CHECK_VECTOR)

LABEL(machine_check)
	EXCEPTION_NO_ERR_CODE(MACHINE_CHECK_VECTOR)

LABEL(simd_exception)
	EXCEPTION_NO_ERR_CODE(SIMD_EXCEPTION_VECTOR)

/*===========================================================================*/
/*				reload_cr3				     */
/*===========================================================================*/
/* PUBLIC void reload_cr3(void); */
ENTRY(reload_cr3)
	push    %ebp
	mov     %esp, %ebp
	mov	%cr3, %eax
	mov	%eax, %cr3
	pop     %ebp
	ret

#ifdef CONFIG_SMP
ENTRY(startup_ap_32)
	/*
	 * we are in protected mode now, %cs is correct and we need to set the
	 * data descriptors before we can touch anything
	 *
	 * first load the regular, highly mapped idt, gdt
	 */

	/*
	 * use the boot stack for now. The running CPUs are already using their
	 * own stack, the rest is still waiting to be booted
	 */
	movw	$KERN_DS_SELECTOR, %ax
	mov	%ax, %ds
	mov	%ax, %ss
	mov	$_C_LABEL(k_boot_stktop) - 4, %esp

	/* load the highly mapped idt, gdt, per-cpu tss */
	call	_C_LABEL(prot_load_selectors)

	jmp	_C_LABEL(smp_ap_boot)
	hlt
#endif

/*===========================================================================*/
/*				data					     */
/*===========================================================================*/

.data
.short	0x526F	/* this must be the first data entry (magic #) */

.bss
k_initial_stack:
.space	K_STACK_SIZE
LABEL(__k_unpaged_k_initial_stktop)

/*
 * the kernel stack
 */
k_boot_stack:
.space	K_STACK_SIZE	/* kernel stack */ /* FIXME use macro here */
LABEL(k_boot_stktop)	/* top of kernel stack */

.balign K_STACK_SIZE
LABEL(k_stacks_start)

/* two pages for each stack, one for data, other as a sandbox */
.space	2 * (K_STACK_SIZE * CONFIG_MAX_CPUS)

LABEL(k_stacks_end)

/* top of kernel stack */
