/*
 * Copyright (c) 2000, 2001, 2002, 2003, 2004, 2005, 2008, 2009, 2010
 *	The President and Fellows of Harvard College.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE UNIVERSITY AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE UNIVERSITY OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Core kernel-level thread system.
 */

#define THREADINLINE

#include <types.h>
#include <kern/errno.h>
#include <lib.h>
#include <array.h>
#include <cpu.h>
#include <spl.h>
#include <spinlock.h>
#include <wchan.h>
#include <thread.h>
#include <threadlist.h>
#include <threadprivate.h>
#include <proc.h>
#include <current.h>
#include <synch.h>
#include <addrspace.h>
#include <mainbus.h>
#include <vnode.h>


/* Magic number used as a guard value on kernel thread stacks. */
#define THREAD_STACK_MAGIC 0xbaadf00d

/* Wait channel. A wchan is protected by an associated, passed-in spinlock. */
struct wchan {
	const char *wc_name;		/* name for this channel */
	struct threadlist wc_threads;	/* list of waiting threads */
};

/* Master array of CPUs. */
DECLARRAY(cpu, static __UNUSED inline);
DEFARRAY(cpu, static __UNUSED inline);
static struct cpuarray allcpus;

static struct lock *wait_lock;
static struct wait_List *wait_list = NULL;

static struct pid_List *pid_list = NULL;
//static struct pid_List *exit_list = NULL;


int switch_fl=1;//,pri_fl=0;

/* Used to wait for secondary CPUs to come online. */
static struct semaphore *cpu_startup_sem;

////////////////////////////////////////////////////////////

/*
 * Stick a magic number on the bottom end of the stack. This will
 * (sometimes) catch kernel stack overflows. Use thread_checkstack()
 * to test this.
 */
static
void
thread_checkstack_init(struct thread *thread)
{
	((uint32_t *)thread->t_stack)[0] = THREAD_STACK_MAGIC;
	((uint32_t *)thread->t_stack)[1] = THREAD_STACK_MAGIC;
	((uint32_t *)thread->t_stack)[2] = THREAD_STACK_MAGIC;
	((uint32_t *)thread->t_stack)[3] = THREAD_STACK_MAGIC;
}

/*
 * Check the magic number we put on the bottom end of the stack in
 * thread_checkstack_init. If these assertions go off, it most likely
 * means you overflowed your stack at some point, which can cause all
 * kinds of mysterious other things to happen.
 *
 * Note that when ->t_stack is NULL, which is the case if the stack
 * cannot be freed (which in turn is the case if the stack is the boot
 * stack, and the thread is the boot thread) this doesn't do anything.
 */
static
void
thread_checkstack(struct thread *thread)
{
	if (thread->t_stack != NULL) {
		KASSERT(((uint32_t*)thread->t_stack)[0] == THREAD_STACK_MAGIC);
		KASSERT(((uint32_t*)thread->t_stack)[1] == THREAD_STACK_MAGIC);
		KASSERT(((uint32_t*)thread->t_stack)[2] == THREAD_STACK_MAGIC);
		KASSERT(((uint32_t*)thread->t_stack)[3] == THREAD_STACK_MAGIC);
	}
}

/*
 * Create a thread. This is used both to create a first thread
 * for each CPU and to create subsequent forked threads.
 */
static
struct thread *
thread_create(const char *name)
{
	struct thread *thread;

	DEBUGASSERT(name != NULL);

	thread = kmalloc(sizeof(*thread));
	if (thread == NULL) {
		return NULL;
	}

	thread->t_name = kstrdup(name);
	if (thread->t_name == NULL) {
		kfree(thread);
		return NULL;
	}
	thread->t_wchan_name = "NEW";
	thread->t_state = S_READY;

	/* Thread subsystem fields */
	thread_machdep_init(&thread->t_machdep);
	threadlistnode_init(&thread->t_listnode, thread);
	thread->t_stack = NULL;
	thread->t_context = NULL;
	thread->t_cpu = NULL;
	thread->t_proc = NULL;

	/* Interrupt state fields */
	thread->t_in_interrupt = false;
	thread->t_curspl = IPL_HIGH;
	thread->t_iplhigh_count = 1; /* corresponding to t_curspl */

	thread->ppid = 0;

	thread->pid = add_pid_table();

	/* If you add to struct thread, be sure to initialize here */
	for(int i=3; i < MAX_FILE_FILETAB; i++)
		thread->fdesc[i] = NULL;

	/* If you add to struct thread, be sure to initialize here */

	return thread;
}

/*
 * Create a CPU structure. This is used for the bootup CPU and
 * also for secondary CPUs.
 *
 * The hardware number (the number assigned by firmware or system
 * board config or whatnot) is tracked separately because it is not
 * necessarily anything sane or meaningful.
 */
struct cpu *
cpu_create(unsigned hardware_number)
{
	struct cpu *c;
	int result;
	char namebuf[16];

	c = kmalloc(sizeof(*c));
	if (c == NULL) {
		panic("cpu_create: Out of memory\n");
	}

	c->c_self = c;
	c->c_hardware_number = hardware_number;

	c->c_curthread = NULL;
	threadlist_init(&c->c_zombies);
	c->c_hardclocks = 0;
	c->c_spinlocks = 0;

	c->c_isidle = false;
	threadlist_init(&c->c_runqueue);
	spinlock_init(&c->c_runqueue_lock);

	c->c_ipi_pending = 0;
	c->c_numshootdown = 0;
	spinlock_init(&c->c_ipi_lock);

	result = cpuarray_add(&allcpus, c, &c->c_number);
	if (result != 0) {
		panic("cpu_create: array_add: %s\n", strerror(result));
	}

	snprintf(namebuf, sizeof(namebuf), "<boot #%d>", c->c_number);
	c->c_curthread = thread_create(namebuf);
	if (c->c_curthread == NULL) {
		panic("cpu_create: thread_create failed\n");
	}
	c->c_curthread->t_cpu = c;

	if (c->c_number == 0) {
		/*
		 * Leave c->c_curthread->t_stack NULL for the boot
		 * cpu. This means we're using the boot stack, which
		 * can't be freed. (Exercise: what would it take to
		 * make it possible to free the boot stack?)
		 */
		/*c->c_curthread->t_stack = ... */
	}
	else {
		c->c_curthread->t_stack = kmalloc(STACK_SIZE);
		if (c->c_curthread->t_stack == NULL) {
			panic("cpu_create: couldn't allocate stack");
		}
		thread_checkstack_init(c->c_curthread);
	}

	/*
	 * If there is no curcpu (or curthread) yet, we are creating
	 * the first (boot) cpu. Initialize curcpu and curthread as
	 * early as possible so that other code can take locks without
	 * exploding.
	 */
	if (!CURCPU_EXISTS()) {
		/*
		 * Initializing curcpu and curthread is
		 * machine-dependent because either of curcpu and
		 * curthread might be defined in terms of the other.
		 */
		INIT_CURCPU(c, c->c_curthread);

		/*
		 * Now make sure both t_cpu and c_curthread are
		 * set. This might be partially redundant with
		 * INIT_CURCPU depending on how things are defined.
		 */
		curthread->t_cpu = curcpu;
		curcpu->c_curthread = curthread;
	}

	result = proc_addthread(kproc, c->c_curthread);
	if (result) {
		panic("cpu_create: proc_addthread:: %s\n", strerror(result));
	}

	cpu_machdep_init(c);

	return c;
}

/*
 * Destroy a thread.
 *
 * This function cannot be called in the victim thread's own context.
 * Nor can it be called on a running thread.
 *
 * (Freeing the stack you're actually using to run is ... inadvisable.)
 */
static
void
thread_destroy(struct thread *thread)
{
	KASSERT(thread != curthread);
	KASSERT(thread->t_state != S_RUN);

	/*
	 * If you add things to struct thread, be sure to clean them up
	 * either here or in thread_exit(). (And not both...)
	 */

	/* Thread subsystem fields */
	KASSERT(thread->t_proc == NULL);
	if (thread->t_stack != NULL) {
		kfree(thread->t_stack);
	}
	threadlistnode_cleanup(&thread->t_listnode);
	thread_machdep_cleanup(&thread->t_machdep);

	/* sheer paranoia */
	thread->t_wchan_name = "DESTROYED";

	int s = splhigh();
for(int i=3; i < MAX_FILE_FILETAB; i++)
{
	if(thread->fdesc[i] != NULL){
		if(thread->fdesc[i]->vnode != NULL) {
			if(thread->fdesc[i]->vnode->vn_opencount <= 1)
				kfree(thread->fdesc[i]->vnode);
			lock_destroy(thread->fdesc[i]->f_lock);
			kfree(thread->fdesc[i]);
		}
	}
}
splx(s);

	kfree(thread->t_name);
	kfree(thread);
}

/*
 * Clean up zombies. (Zombies are threads that have exited but still
 * need to have thread_destroy called on them.)
 *
 * The list of zombies is per-cpu.
 */
static
void
exorcise(void)
{
	struct thread *z;

	while ((z = threadlist_remhead(&curcpu->c_zombies)) != NULL) {
		KASSERT(z != curthread);
		KASSERT(z->t_state == S_ZOMBIE);
		thread_destroy(z);
	}
}

/*
 * On panic, stop the thread system (as much as is reasonably
 * possible) to make sure we don't end up letting any other threads
 * run.
 */
void
thread_panic(void)
{
	/*
	 * Kill off other CPUs.
	 *
	 * We could wait for them to stop, except that they might not.
	 */
	ipi_broadcast(IPI_PANIC);

	/*
	 * Drop runnable threads on the floor.
	 *
	 * Don't try to get the run queue lock; we might not be able
	 * to.  Instead, blat the list structure by hand, and take the
	 * risk that it might not be quite atomic.
	 */
	curcpu->c_runqueue.tl_count = 0;
	curcpu->c_runqueue.tl_head.tln_next = &curcpu->c_runqueue.tl_tail;
	curcpu->c_runqueue.tl_tail.tln_prev = &curcpu->c_runqueue.tl_head;

	/*
	 * Ideally, we want to make sure sleeping threads don't wake
	 * up and start running. However, there's no good way to track
	 * down all the wchans floating around the system. Another
	 * alternative would be to set a global flag to make the wchan
	 * wakeup operations do nothing; but that would mean we
	 * ourselves couldn't sleep to wait for an I/O completion
	 * interrupt, and we'd like to be able to do that if the
	 * system isn't that badly hosed.
	 *
	 * So, do nothing else here.
	 *
	 * This may prove inadequate in practice and further steps
	 * might be needed. It may also be necessary to go through and
	 * forcibly unlock all locks or the like...
	 */
}

/*
 * At system shutdown, ask the other CPUs to switch off.
 */
void
thread_shutdown(void)
{
	/*
	 * Stop the other CPUs.
	 *
	 * We should probably wait for them to stop and shut them off
	 * on the system board.
	 */
	ipi_broadcast(IPI_OFFLINE);
}

/*
 * Thread system initialization.
 */
void
thread_bootstrap(void)
{
	struct cpu *bootcpu;
	struct thread *bootthread;
	cpuarray_init(&allcpus);

	/*
	 * Create the cpu structure for the bootup CPU, the one we're
	 * currently running on. Assume the hardware number is 0; that
	 * might be updated later by mainbus-type code. This also
	 * creates a thread structure for the first thread, the one
	 * that's already implicitly running when the kernel is
	 * started from the bootloader.
	 */
	KASSERT(CURCPU_EXISTS() == false);
	(void)cpu_create(0);
	KASSERT(CURCPU_EXISTS() == true);
	bootthread = bootcpu->c_curthread;

	/*
   * Initializing curcpu and curthread is machine-dependent
   * because either of curcpu and curthread might be defined in
   * terms of the other.
   */
	INIT_CURCPU(bootcpu, bootthread);

	/* cpu_create() should also have set t_proc. */
	KASSERT(curcpu != NULL);
	KASSERT(curthread != NULL);
	KASSERT(curthread->t_proc != NULL);
	KASSERT(curthread->t_proc == kproc);

	/*
	 * Now make sure both t_cpu and c_curthread are set. This
	 * might be partially redundant with INIT_CURCPU depending on
	 * how things are defined.
	 */
	curthread->t_cpu = curcpu;
	curcpu->c_curthread = curthread;
	curthread->pid = add_pid_table();

	/* Done */
}

/*
 * New CPUs come here once MD initialization is finished. curthread
 * and curcpu should already be initialized.
 *
 * Other than clearing thread_start_cpus() to continue, we don't need
 * to do anything. The startup thread can just exit; we only need it
 * to be able to get into thread_switch() properly.
 */
void
cpu_hatch(unsigned software_number)
{
	char buf[64];

	KASSERT(curcpu != NULL);
	KASSERT(curthread != NULL);
	KASSERT(curcpu->c_number == software_number);

	spl0();
	cpu_identify(buf, sizeof(buf));

	kprintf("cpu%u: %s\n", software_number, buf);

	V(cpu_startup_sem);
	thread_exit();
}

/*
 * Start up secondary cpus. Called from boot().
 */
void
thread_start_cpus(void)
{
	char buf[64];
	unsigned i;

	cpu_identify(buf, sizeof(buf));
	kprintf("cpu0: %s\n", buf);

	cpu_startup_sem = sem_create("cpu_hatch", 0);
	mainbus_start_cpus();

	for (i=0; i<cpuarray_num(&allcpus) - 1; i++) {
		P(cpu_startup_sem);
	}
	sem_destroy(cpu_startup_sem);
	cpu_startup_sem = NULL;
}

/*
 * Make a thread runnable.
 *
 * targetcpu might be curcpu; it might not be, too.
 */
static
void
thread_make_runnable(struct thread *target, bool already_have_lock)
{
	struct cpu *targetcpu;

	/* Lock the run queue of the target thread's cpu. */
	targetcpu = target->t_cpu;

	if (already_have_lock) {
		/* The target thread's cpu should be already locked. */
		KASSERT(spinlock_do_i_hold(&targetcpu->c_runqueue_lock));
	}
	else {
		spinlock_acquire(&targetcpu->c_runqueue_lock);
	}

	/* Target thread is now ready to run; put it on the run queue. */
	target->t_state = S_READY;
	threadlist_addtail(&targetcpu->c_runqueue, target);

	if (targetcpu->c_isidle && targetcpu != curcpu->c_self) {
		/*
		 * Other processor is idle; send interrupt to make
		 * sure it unidles.
		 */
		ipi_send(targetcpu, IPI_UNIDLE);
	}

	if (!already_have_lock) {
		spinlock_release(&targetcpu->c_runqueue_lock);
	}
}

/*
 * Create a new thread based on an existing one.
 *
 * The new thread has name NAME, and starts executing in function
 * ENTRYPOINT. DATA1 and DATA2 are passed to ENTRYPOINT.
 *
 * The new thread is created in the process P. If P is null, the
 * process is inherited from the caller. It will start on the same CPU
 * as the caller, unless the scheduler intervenes first.
 */
int
thread_fork(const char *name,
	    struct proc *proc,
	    void (*entrypoint)(void *data1, unsigned long data2),
	    void *data1, unsigned long data2)
{
	struct thread *newthread;
	int result;

	newthread = thread_create(name);
	if (newthread == NULL) {
		return ENOMEM;
	}

	/* Allocate a stack */
	newthread->t_stack = kmalloc(STACK_SIZE);
	if (newthread->t_stack == NULL) {
		thread_destroy(newthread);
		return ENOMEM;
	}
	thread_checkstack_init(newthread);

	/*
	 * Now we clone various fields from the parent thread.
	 */

	/* Thread subsystem fields */
	newthread->t_cpu = curthread->t_cpu;

	/* Attach the new thread to its process */
	if (proc == NULL) {
		proc = curthread->t_proc;
	}
	result = proc_addthread(proc, newthread);
	if (result) {
		/* thread_destroy will clean up the stack */
		thread_destroy(newthread);
		return result;
	}


	int s = splhigh();
	splx(s);
	newthread->ppid = 0;

	int result;
	if(curthread->fdesc[0] == NULL || curthread->fdesc[1] == NULL || curthread->fdesc[2] == NULL)
		result = fdesc_init(newthread);// initialize and open stdin ,stdout , stderr file descriptor
	if(result)
	{
		panic("fdesc_init failed\n");
	}

	int i;
  	for(i = 0; i < MAX_FILE_FILETAB; i++) {
		if(curthread->fdesc[i] != NULL)
    			newthread->fdesc[i] = curthread->fdesc[i]; // copy parent fdesc to child fdesc
  	}

	/*
	 * Because new threads come out holding the cpu runqueue lock
	 * (see notes at bottom of thread_switch), we need to account
	 * for the spllower() that will be done releasing it.
	 */
	newthread->t_iplhigh_count++;

	/* Set up the switchframe so entrypoint() gets called */
	switchframe_init(newthread, entrypoint, data1, data2);

	/* Lock the current cpu's run queue and make the new thread runnable */
	thread_make_runnable(newthread, false);

	if(wait_lock == NULL)
			wait_lock = lock_create((char*)curthread->t_name);// generate lock for current thread

	return 0;
}

/*
 * High level, machine-independent context switch code.
 *
 * The current thread is queued appropriately and its state is changed
 * to NEWSTATE; another thread to run is selected and switched to.
 *
 * If NEWSTATE is S_SLEEP, the thread is queued on the wait channel
 * WC, protected by the spinlock LK. Otherwise WC and Lk should be
 * NULL.
 */
static
void
thread_switch(threadstate_t newstate, struct wchan *wc, struct spinlock *lk)
{
	struct thread *cur, *next;
	int spl;

	DEBUGASSERT(curcpu->c_curthread == curthread);
	DEBUGASSERT(curthread->t_cpu == curcpu->c_self);

	/* Explicitly disable interrupts on this processor */
	spl = splhigh();

	cur = curthread;

	/*
	 * If we're idle, return without doing anything. This happens
	 * when the timer interrupt interrupts the idle loop.
	 */
	if (curcpu->c_isidle) {
		splx(spl);
		return;
	}

	/* Check the stack guard band. */
	thread_checkstack(cur);

	/* Lock the run queue. */
	spinlock_acquire(&curcpu->c_runqueue_lock);

	/* Micro-optimization: if nothing to do, just return */
	if (newstate == S_READY && threadlist_isempty(&curcpu->c_runqueue)) {
		spinlock_release(&curcpu->c_runqueue_lock);
		splx(spl);
		return;
	}

	/* Put the thread in the right place. */
	switch (newstate) {
	    case S_RUN:
		panic("Illegal S_RUN in thread_switch\n");
	    case S_READY:
		thread_make_runnable(cur, true /*have lock*/);
		break;
	    case S_SLEEP:
		cur->t_wchan_name = wc->wc_name;
		/*
		 * Add the thread to the list in the wait channel, and
		 * unlock same. To avoid a race with someone else
		 * calling wchan_wake*, we must keep the wchan's
		 * associated spinlock locked from the point the
		 * caller of wchan_sleep locked it until the thread is
		 * on the list.
		 */
		threadlist_addtail(&wc->wc_threads, cur);
		spinlock_release(lk);
		break;
	    case S_ZOMBIE:
		cur->t_wchan_name = "ZOMBIE";
		threadlist_addtail(&curcpu->c_zombies, cur);
		break;
	}
	cur->t_state = newstate;

	/*
	 * Get the next thread. While there isn't one, call cpu_idle().
	 * curcpu->c_isidle must be true when cpu_idle is
	 * called. Unlock the runqueue while idling too, to make sure
	 * things can be added to it.
	 *
	 * Note that we don't need to unlock the runqueue atomically
	 * with idling; becoming unidle requires receiving an
	 * interrupt (either a hardware interrupt or an interprocessor
	 * interrupt from another cpu posting a wakeup) and idling
	 * *is* atomic with respect to re-enabling interrupts.
	 *
	 * Note that c_isidle becomes true briefly even if we don't go
	 * idle. However, because one is supposed to hold the runqueue
	 * lock to look at it, this should not be visible or matter.
	 */

	/* The current cpu is now idle. */
	curcpu->c_isidle = true;
	do {
		next = threadlist_remhead(&curcpu->c_runqueue);
		if (next == NULL) {
			spinlock_release(&curcpu->c_runqueue_lock);
			cpu_idle();
			spinlock_acquire(&curcpu->c_runqueue_lock);
		}
	} while (next == NULL);
	curcpu->c_isidle = false;

	/*
	 * Note that curcpu->c_curthread may be the same variable as
	 * curthread and it may not be, depending on how curthread and
	 * curcpu are defined by the MD code. We'll assign both and
	 * assume the compiler will optimize one away if they're the
	 * same.
	 */
	curcpu->c_curthread = next;
	curthread = next;

	/* do the switch (in assembler in switch.S) */
	switchframe_switch(&cur->t_context, &next->t_context);

	/*
	 * When we get to this point we are either running in the next
	 * thread, or have come back to the same thread again,
	 * depending on how you look at it. That is,
	 * switchframe_switch returns immediately in another thread
	 * context, which in general will be executing here with a
	 * different stack and different values in the local
	 * variables. (Although new threads go to thread_startup
	 * instead.) But, later on when the processor, or some
	 * processor, comes back to the previous thread, it's also
	 * executing here with the *same* value in the local
	 * variables.
	 *
	 * The upshot, however, is as follows:
	 *
	 *    - The thread now currently running is "cur", not "next",
	 *      because when we return from switchrame_switch on the
	 *      same stack, we're back to the thread that
	 *      switchframe_switch call switched away from, which is
	 *      "cur".
	 *
	 *    - "cur" is _not_ the thread that just *called*
	 *      switchframe_switch.
	 *
	 *    - If newstate is S_ZOMB we never get back here in that
	 *      context at all.
	 *
	 *    - If the thread just chosen to run ("next") was a new
	 *      thread, we don't get to this code again until
	 *      *another* context switch happens, because when new
	 *      threads return from switchframe_switch they teleport
	 *      to thread_startup.
	 *
	 *    - At this point the thread whose stack we're now on may
	 *      have been migrated to another cpu since it last ran.
	 *
	 * The above is inherently confusing and will probably take a
	 * while to get used to.
	 *
	 * However, the important part is that code placed here, after
	 * the call to switchframe_switch, does not necessarily run on
	 * every context switch. Thus any such code must be either
	 * skippable on some switches or also called from
	 * thread_startup.
	 */


	/* Clear the wait channel and set the thread state. */
	cur->t_wchan_name = NULL;
	cur->t_state = S_RUN;

	/* Unlock the run queue. */
	spinlock_release(&curcpu->c_runqueue_lock);

	/* Activate our address space in the MMU. */
	as_activate();

	/* Clean up dead threads. */
	exorcise();

	/* Turn interrupts back on. */
	splx(spl);
}

/*
 * This function is where new threads start running. The arguments
 * ENTRYPOINT, DATA1, and DATA2 are passed through from thread_fork.
 *
 * Because new code comes here from inside the middle of
 * thread_switch, the beginning part of this function must match the
 * tail of thread_switch.
 */
void
thread_startup(void (*entrypoint)(void *data1, unsigned long data2),
	       void *data1, unsigned long data2)
{
	struct thread *cur;

	cur = curthread;

	/* Clear the wait channel and set the thread state. */
	cur->t_wchan_name = NULL;
	cur->t_state = S_RUN;

	/* Release the runqueue lock acquired in thread_switch. */
	spinlock_release(&curcpu->c_runqueue_lock);

	/* Activate our address space in the MMU. */
	as_activate();

	/* Clean up dead threads. */
	exorcise();

	/* Enable interrupts. */
	spl0();

	/* Call the function. */
	entrypoint(data1, data2);

	/* Done. */
	thread_exit();
}

/*
 * Cause the current thread to exit.
 *
 * The parts of the thread structure we don't actually need to run
 * should be cleaned up right away. The rest has to wait until
 * thread_destroy is called from exorcise().
 *
 * Does not return.
 */
void
thread_exit(void)
{
	struct thread *cur;

	cur = curthread;

	/*
	 * Detach from our process. You might need to move this action
	 * around, depending on how your wait/exit works.
	 */
	proc_remthread(cur);

	/* Make sure we *are* detached (move this only if you're sure!) */
	KASSERT(cur->t_proc == NULL);

	/* Check the stack guard band. */
	thread_checkstack(cur);

	/* Interrupts off on this processor */
        splhigh();
	thread_switch(S_ZOMBIE, NULL, NULL);
	panic("braaaaaaaiiiiiiiiiiinssssss\n");
}

/*
 * Yield the cpu to another process, but stay runnable.
 */
void
thread_yield(void)
{
	thread_switch(S_READY, NULL, NULL);
}

////////////////////////////////////////////////////////////

/*
 * Scheduler.
 *
 * This is called periodically from hardclock(). It should reshuffle
 * the current CPU's run queue by job priority.
 */

void
schedule(void)
{
	/*
	 * You can write this. If we do nothing, threads will run in
	 * round-robin fashion.
	 */
}

/*
 * Thread migration.
 *
 * This is also called periodically from hardclock(). If the current
 * CPU is busy and other CPUs are idle, or less busy, it should move
 * threads across to those other other CPUs.
 *
 * Migrating threads isn't free because of cache affinity; a thread's
 * working cache set will end up having to be moved to the other CPU,
 * which is fairly slow. The tradeoff between this performance loss
 * and the performance loss due to underutilization of some CPUs is
 * something that needs to be tuned and probably is workload-specific.
 *
 * For here and now, because we know we're running on System/161 and
 * System/161 does not (yet) model such cache effects, we'll be very
 * aggressive.
 */
void
thread_consider_migration(void)
{
	unsigned my_count, total_count, one_share, to_send;
	unsigned i, numcpus;
	struct cpu *c;
	struct threadlist victims;
	struct thread *t;

	my_count = total_count = 0;
	numcpus = cpuarray_num(&allcpus);
	for (i=0; i<numcpus; i++) {
		c = cpuarray_get(&allcpus, i);
		spinlock_acquire(&c->c_runqueue_lock);
		total_count += c->c_runqueue.tl_count;
		if (c == curcpu->c_self) {
			my_count = c->c_runqueue.tl_count;
		}
		spinlock_release(&c->c_runqueue_lock);
	}

	one_share = DIVROUNDUP(total_count, numcpus);
	if (my_count < one_share) {
		return;
	}

	to_send = my_count - one_share;
	threadlist_init(&victims);
	spinlock_acquire(&curcpu->c_runqueue_lock);
	for (i=0; i<to_send; i++) {
		t = threadlist_remtail(&curcpu->c_runqueue);
		threadlist_addhead(&victims, t);
	}
	spinlock_release(&curcpu->c_runqueue_lock);

	for (i=0; i < numcpus && to_send > 0; i++) {
		c = cpuarray_get(&allcpus, i);
		if (c == curcpu->c_self) {
			continue;
		}
		spinlock_acquire(&c->c_runqueue_lock);
		while (c->c_runqueue.tl_count < one_share && to_send > 0) {
			t = threadlist_remhead(&victims);
			/*
			 * Ordinarily, curthread will not appear on
			 * the run queue. However, it can under the
			 * following circumstances:
			 *   - it went to sleep;
			 *   - the processor became idle, so it
			 *     remained curthread;
			 *   - it was reawakened, so it was put on the
			 *     run queue;
			 *   - and the processor hasn't fully unidled
			 *     yet, so all these things are still true.
			 *
			 * If the timer interrupt happens at (almost)
			 * exactly the proper moment, we can come here
			 * while things are in this state and see
			 * curthread. However, *migrating* curthread
			 * can cause bad things to happen (Exercise:
			 * Why? And what?) so shuffle it to the end of
			 * the list and decrement to_send in order to
			 * skip it. Then it goes back on our own run
			 * queue below.
			 */
			if (t == curthread) {
				threadlist_addtail(&victims, t);
				to_send--;
				continue;
			}

			t->t_cpu = c;
			threadlist_addtail(&c->c_runqueue, t);
			DEBUG(DB_THREADS,
			      "Migrated thread %s: cpu %u -> %u",
			      t->t_name, curcpu->c_number, c->c_number);
			to_send--;
			if (c->c_isidle) {
				/*
				 * Other processor is idle; send
				 * interrupt to make sure it unidles.
				 */
				ipi_send(c, IPI_UNIDLE);
			}
		}
		spinlock_release(&c->c_runqueue_lock);
	}

	/*
	 * Because the code above isn't atomic, the thread counts may have
	 * changed while we were working and we may end up with leftovers.
	 * Don't panic; just put them back on our own run queue.
	 */
	if (!threadlist_isempty(&victims)) {
		spinlock_acquire(&curcpu->c_runqueue_lock);
		while ((t = threadlist_remhead(&victims)) != NULL) {
			threadlist_addtail(&curcpu->c_runqueue, t);
		}
		spinlock_release(&curcpu->c_runqueue_lock);
	}

	KASSERT(threadlist_isempty(&victims));
	threadlist_cleanup(&victims);
}

////////////////////////////////////////////////////////////

/*
 * Wait channel functions
 */

/*
 * Create a wait channel. NAME is a symbolic string name for it.
 * This is what's displayed by ps -alx in Unix.
 *
 * NAME should generally be a string constant. If it isn't, alternate
 * arrangements should be made to free it after the wait channel is
 * destroyed.
 */
struct wchan *
wchan_create(const char *name)
{
	struct wchan *wc;

	wc = kmalloc(sizeof(*wc));
	if (wc == NULL) {
		return NULL;
	}
	spinlock_init(&wc->wc_lock);
	threadlist_init(&wc->wc_threads);
	wc->wc_name = name;

	return wc;
}

/*
 * Destroy a wait channel. Must be empty and unlocked.
 * (The corresponding cleanup functions require this.)
 */
void
wchan_destroy(struct wchan *wc)
{
	spinlock_cleanup(&wc->wc_lock);
	threadlist_cleanup(&wc->wc_threads);
	kfree(wc);
}

/*
 * Lock and unlock a wait channel, respectively.
 */
void
wchan_lock(struct wchan *wc)
{
	spinlock_acquire(&wc->wc_lock);
}

void
wchan_unlock(struct wchan *wc)
{
	spinlock_release(&wc->wc_lock);
}

/*
 * Yield the cpu to another process, and go to sleep, on the specified
 * wait channel WC, whose associated spinlock is LK. Calling wakeup on
 * the channel will make the thread runnable again. The spinlock must
 * be locked. The call to thread_switch unlocks it; we relock it
 * before returning.
 */
void
wchan_sleep(struct wchan *wc, struct spinlock *lk)
{
	/* may not sleep in an interrupt handler */
	KASSERT(!curthread->t_in_interrupt);

	/* must hold the spinlock */
	KASSERT(spinlock_do_i_hold(lk));

	/* must not hold other spinlocks */
	KASSERT(curcpu->c_spinlocks == 1);

	thread_switch(S_SLEEP, wc, lk);
	spinlock_acquire(lk);
}

/*
 * Wake up one thread sleeping on a wait channel.
 */
void
wchan_wakeone(struct wchan *wc, struct spinlock *lk)
{
	struct thread *target;

	KASSERT(spinlock_do_i_hold(lk));

	/* Grab a thread from the channel */
	target = threadlist_remhead(&wc->wc_threads);

	if (target == NULL) {
		/* Nobody was sleeping. */
		return;
	}

	/*
	 * Note that thread_make_runnable acquires a runqueue lock
	 * while we're holding LK. This is ok; all spinlocks
	 * associated with wchans must come before the runqueue locks,
	 * as we also bridge from the wchan lock to the runqueue lock
	 * in thread_switch.
	 */

	thread_make_runnable(target, false);
}

/*
 * Wake up all threads sleeping on a wait channel.
 */
void
wchan_wakeall(struct wchan *wc, struct spinlock *lk)
{
	struct thread *target;
	struct threadlist list;

	KASSERT(spinlock_do_i_hold(lk));

	threadlist_init(&list);

	/*
	 * Grab all the threads from the channel, moving them to a
	 * private list.
	 */
	while ((target = threadlist_remhead(&wc->wc_threads)) != NULL) {
		threadlist_addtail(&list, target);
	}

	/*
	 * We could conceivably sort by cpu first to cause fewer lock
	 * ops and fewer IPIs, but for now at least don't bother. Just
	 * make each thread runnable.
	 */
	while ((target = threadlist_remhead(&list)) != NULL) {
		thread_make_runnable(target, false);
	}

	threadlist_cleanup(&list);
}

/*
 * Return nonzero if there are no threads sleeping on the channel.
 * This is meant to be used only for diagnostic purposes.
 */
bool
wchan_isempty(struct wchan *wc, struct spinlock *lk)
{
	bool ret;

	KASSERT(spinlock_do_i_hold(lk));
	ret = threadlist_isempty(&wc->wc_threads);

	return ret;
}

////////////////////////////////////////////////////////////

/*
 * Machine-independent IPI handling
 */

/*
 * Send an IPI (inter-processor interrupt) to the specified CPU.
 */
void
ipi_send(struct cpu *target, int code)
{
	KASSERT(code >= 0 && code < 32);

	spinlock_acquire(&target->c_ipi_lock);
	target->c_ipi_pending |= (uint32_t)1 << code;
	mainbus_send_ipi(target);
	spinlock_release(&target->c_ipi_lock);
}

/*
 * Send an IPI to all CPUs.
 */
void
ipi_broadcast(int code)
{
	unsigned i;
	struct cpu *c;

	for (i=0; i < cpuarray_num(&allcpus); i++) {
		c = cpuarray_get(&allcpus, i);
		if (c != curcpu->c_self) {
			ipi_send(c, code);
		}
	}
}

/*
 * Send a TLB shootdown IPI to the specified CPU.
 */
void
ipi_tlbshootdown(struct cpu *target, const struct tlbshootdown *mapping)
{
	unsigned n;

	spinlock_acquire(&target->c_ipi_lock);

	n = target->c_numshootdown;
	if (n == TLBSHOOTDOWN_MAX) {
		/*
		 * If you have problems with this panic going off,
		 * consider: (1) increasing the maximum, (2) putting
		 * logic here to sleep until space appears (may
		 * interact awkwardly with VM system locking), (3)
		 * putting logic here to coalesce requests together,
		 * and/or (4) improving VM system state tracking to
		 * reduce the number of unnecessary shootdowns.
		 */
		panic("ipi_tlbshootdown: Too many shootdowns queued\n");
	}
	else {
		target->c_shootdown[n] = *mapping;
		target->c_numshootdown = n+1;
	}

	target->c_ipi_pending |= (uint32_t)1 << IPI_TLBSHOOTDOWN;
	mainbus_send_ipi(target);

	spinlock_release(&target->c_ipi_lock);
}

/*
 * Handle an incoming interprocessor interrupt.
 */
void
interprocessor_interrupt(void)
{
	uint32_t bits;
	unsigned i;

	spinlock_acquire(&curcpu->c_ipi_lock);
	bits = curcpu->c_ipi_pending;

	if (bits & (1U << IPI_PANIC)) {
		/* panic on another cpu - just stop dead */
		spinlock_release(&curcpu->c_ipi_lock);
		cpu_halt();
	}
	if (bits & (1U << IPI_OFFLINE)) {
		/* offline request */
		spinlock_release(&curcpu->c_ipi_lock);
		spinlock_acquire(&curcpu->c_runqueue_lock);
		if (!curcpu->c_isidle) {
			kprintf("cpu%d: offline: warning: not idle\n",
				curcpu->c_number);
		}
		spinlock_release(&curcpu->c_runqueue_lock);
		kprintf("cpu%d: offline.\n", curcpu->c_number);
		cpu_halt();
	}
	if (bits & (1U << IPI_UNIDLE)) {
		/*
		 * The cpu has already unidled itself to take the
		 * interrupt; don't need to do anything else.
		 */
	}
	if (bits & (1U << IPI_TLBSHOOTDOWN)) {
		/*
		 * Note: depending on your VM system locking you might
		 * need to release the ipi lock while calling
		 * vm_tlbshootdown.
		 */
		for (i=0; i<curcpu->c_numshootdown; i++) {
			vm_tlbshootdown(&curcpu->c_shootdown[i]);
		}
		curcpu->c_numshootdown = 0;
	}

	curcpu->c_ipi_pending = 0;
	spinlock_release(&curcpu->c_ipi_lock);
}

//////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////
//  Process Function - fork(),exec()
//
/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////

/**
* @brief duplicate the currently running process
*
*	@param[in] tf : pointer to trapframe structure
*	@param[out] retval: pointer to int
*
* @return int
*
*/

int
sys_fork(struct trapframe *tf, int32_t * retval)
{
	struct thread *newthread;
	lock_acquire(wait_lock);
	newthread = thread_create(curthread->t_name); // - Creat child thread
	lock_release(wait_lock);
	if (newthread == NULL) {
		return ENOMEM; /// - Sufficient virtual memory for the new process was not available
	}


	/* Allocate a stack from kernel heap in order to save parent trap trapframe*/
	newthread->t_stack = (char *)kmalloc(STACK_SIZE);
	if (newthread->t_stack == NULL) {
		thread_destroy(newthread);
		*retval = 1;
		return ENOMEM; // - failed to allocate the necessary kernel structures because memory is tight
	}
	thread_checkstack_init(newthread);

	/**
	 * Now we clone various fields from the parent thread.
	 */

	// - Copy Thread subsystem fields from parent to child
	newthread->t_cpu = curthread->t_cpu;


	//kprintf("\nstack initialized process: %d\n",newthread->pid);

	int s = splhigh(); // - disable interrupts
	/* VM fields */
	/**
	 * do not clone address space -- let caller decide on that
	 *
	 * as_copy will allocate a struct addrspace and also copy the address space contents
	 *
	 */
	#if OPT_DUMBVM
		int result = as_copy(curthread->t_proc->p_addrspace, &newthread->t_proc->p_addrspace);
	#else
		int result = as_copy(curthread->t_proc->p_addrspace, &newthread->t_proc->p_addrspace, newthread->pid);
	#endif

	if(result) {
		panic("\nno address space defined %d\n",result);
		return EINVAL;

	}


	// - copy the parent trap frame so that we can access it later on
	memcpy(&newthread->t_stack[16], tf, (sizeof(struct trapframe)));

	splx(s); // - restore the old interrupt level

	// - VFS fields
	if (curthread->t_proc->p_cwd != NULL) {
		VOP_INCREF(curthread->t_proc->p_cwd);
		newthread->t_proc->p_cwd = curthread->t_proc->p_cwd; // copy current work directory from parent to child
	}

	//result = fdesc_init(newthread);
	if(result) {
		panic("fdesc_init failed\n");

	}

	//- copy parent file table contents to child
	int i;
  	for(i = 0; i < MAX_FILE_FILETAB; i++) {
		if(curthread->fdesc[i] != NULL)
    			newthread->fdesc[i] = curthread->fdesc[i];
  	}

  // - save parent id in child ppid
	newthread->ppid = curthread->pid;

	/**
	 * Because new threads come out holding the cpu runqueue lock
	 * (see notes at bottom of thread_switch), we need to account
	 * for the spllower() that will be done releasing it.
	 *
	 * we used this based on thread_fork code
	 *
	 */
	newthread->t_iplhigh_count++;


	/**
	 * Set up the switchframe so entrypoint() gets called
	 *
	 * switchframe_init use to initialize the switchframe of a new thread, which is
	 * *not* the one that is currently running.
	 *
	 * enter_forked_process in syscall.c is the first function executed when child thread got run
	 * see the explanation thear
	 */
	switchframe_init(newthread,enter_forked_process,(void *)&newthread->t_stack[16], 0);

 /**
 * Note that thread_creat will set newly created child thread runnable and try to switch to it immediately.
 * So it's highly possible that before thread_creat returns, the child thread is already running.
 * This is not desired since we need to copy other stuff, like file table, to child thread after thread_fork.
 * We definitely don't want the child thread running without a file table.
 * So we need to prevent child thread from running until parent thread set everything up.
 * and call thread_make_runnable in last stage of this sys call .
 *
 */
	/* Lock the current cpu's run queue and make the new thread runnable */
	thread_make_runnable(newthread, false);

	/*
	 * Return new thread structure if it's wanted. Note that using
	 * the thread structure from the parent thread should be done
	 * only with caution, because in general the child thread
	 * might exit at any time.
	 */
	*retval = newthread->pid;
	/*if (ret != NULL) {
		ret = newthread;
	}*/

	//kprintf("\nsys_fork: just before return\n");
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////
//
//		Process Management Fuctions
//
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief allocate a pid list in prder to save our threads pids
 *
 * return pointer to pid_List
 *
 */
struct pid_List* alloc_pid_table(){
	struct pid_List *node;
	node = (struct pid_List*)kmalloc(sizeof(struct pid_List *));
	node->pid = 0;
	node->next = NULL;
	return node;
}

/**
 * @brief find a pid in pid_List
 *
 *	@param[in] pid:
 *
 * return int
 *
 */
int pid_exists (pid_t pid){
	if(pid_list == NULL)
		panic("no pid table exists\n");
	struct pid_List *curr;
	curr = pid_list;
	while(curr->next != NULL)
	{
		if(curr->pid == pid)
			break;
		curr = curr->next;
	}
	if(curr->pid != pid)
		return EINVAL;
	return 0;
}

/**
 * @brief add a pid to pid_List
 *
 *
 * return pid_t
 *
 */
pid_t add_pid_table(){

	if(pid_list == NULL){
		pid_list = alloc_pid_table();
		if(pid_list == NULL)
			return ENOMEM;
		pid_list->pid = __PID_MIN;
		pid_list->next = NULL;
		return pid_list->pid;
	}
	struct pid_List *node;
	struct pid_List *curr, *prev;
	prev = pid_list;
	curr = prev-> next;
	while(curr != NULL)
	{
		if(prev->pid == curr->pid)
			break;
		prev = curr;
		curr = curr->next;
	}
	if(prev->pid > MAX_PID)
		return EINVAL;
	node = alloc_pid_table();
	if(node == NULL)
		return ENOMEM;
	node->pid = prev->pid+1;
	node->next = prev->next;
	prev->next = node;
	return node->pid;
}

/**
 * @brief remove a pid from pid_list
 *
 *	@param[in] pid:
 *
 * return int
 *
 */
int remove_pid_table(pid_t pid){

	if(pid < 2)
		return 0;
	if(pid_list == NULL)
		panic("no pid table in remove\n");
	struct pid_List *curr, *prev;
	prev = pid_list;
	curr = prev-> next;
	if(curr == NULL)
	{
		pid_list = NULL;
		kfree(prev);
		return 0;
	}
	while(curr != NULL)
	{
		if(curr->pid == pid)
			break;
		prev = curr;
		curr = curr->next;
	}
	if(curr == NULL)
		return EINVAL;
	prev->next=curr->next;
	kfree(curr);
	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
//
//		waitpid functions
//
////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief allocate a wait_list
 *
 * return struct wait_List
 *
 */
struct wait_List* alloc_wait_list(){
	struct wait_List *node;
	node = (struct wait_List *)kmalloc(sizeof (struct wait_List *));
	node->pid = 0;
	node->wl_next = NULL;
	return node;
}

/**
 * @brief find a process in wait list
 *
 *	@param[in] pid:
 *
 * return struct wait_List
 *
 */
struct wait_List* get_waiting_pid(pid_t pid){
	if(wait_list == NULL)
		return wait_list;
	struct wait_List *trav;
	trav = wait_list;
	while(trav != NULL)
	{
		if(trav->pid == pid)
			break;
	}
	return trav;
}

/**
 * @brief add new node to wait list
 *
 *	@param[in] node: pointer to struct wait_List
 *
 * return struct wait_List
 *
 */
int add_wait_list(struct wait_List *node){
	if(wait_list == NULL)	{
		return EINVAL;
	}
	struct wait_List *trav;
	trav = wait_list;
	while(trav->wl_next != NULL)
	{
		trav=trav->wl_next;
	}
	trav->wl_next = node;
	return 0;
}

/**
 * @brief remove a node from wait list
 *
 *	@param[in] node: pointer to struct wait_List
 *
 * return struct wait_List
 *
 */
int remove_wait_list(struct wait_List *node)
{
	pid_t pid = node->pid;
	if( wait_list == NULL)
	{
		panic("no wait list");
		return EINVAL;
	}
	if(node == NULL)
	{
		panic("no node list");
		return EINVAL;
	}
	if(wait_list == node)
	{
		wait_list = node->next;
		kfree(node->wait_chan_exit);
		kfree(node);
		return 0;
	}

	struct wait_List *curr, *prev;
	curr = wait_list;
	while(curr != NULL)
	{
		if(curr == node && curr->pid == pid)
		{
			prev->wl_next = curr->wl_next;
			kfree(curr->wait_chan_exit);
			kfree(curr);
			break;
		}
		prev = curr;
		curr = curr->wl_next;
	}
	return 0;
}

/**
* @brief open or crear file with filename
*
*	@param[in]  pid
*	@param[in]  options
*	@param[out] status
*	@param[out] retval: pointer to int
*
* @return int
*
*/

int sys_waitpid(pid_t pid, int *status, int options,int32_t *retval){

	(void) options;
	int stat;
	int result;
	lock_acquire(wait_lock); /// - Get the wait_lock
	pid_t wait_pid = curthread->pid;
	/// - copyin copies LEN bytes from a user-space address USERSRC to a kernel-space address DEST & return 0 on success
	result = copyin((userptr_t)status,&stat,sizeof(status));
	if(result && curthread->ppid != 0)
	{
		lock_release(wait_lock); /// - Free the wait_lock
		*retval = -1;
		return result;
	}

 /// - if process not exists
	if(pid_exists(pid))
	{
		lock_release(wait_lock);
		*retval = -1;
		return ESRCH;

	}

	/// - pid named the process that is not child of current process
 if (pid <= wait_pid){

	 lock_release(wait_lock);
	 *retval = -1;
	 return ECHILD;
 }

 /// - status argument is invallid pointer to int in NULL
	/*if(status == NULL)
	{
		lock_release(wait_lock);
		*retval = -1;
		return EFAULT;
	}*/


 /// we consider option is 0
	if(options != 0)
	{
		*retval = -1;
		lock_release(wait_lock);
		return EINVAL;
	}

	struct wait_List *node;
	//kprintf("\nin sys_waitpid - Hooray\n");
	if(wait_list == NULL)
	{
		wait_list = alloc_wait_list();
		wait_list->pid = pid;
		wait_list->wait_chan_exit = wchan_create((char *)pid);
		wchan_lock(wait_list->wait_chan_exit);
		//kprintf("\nputting thread to sleep\n");
		lock_release(wait_lock);
		wchan_sleep(wait_list->wait_chan_exit);/// The current thread is suspended until awakened by someone else
		lock_acquire(wait_lock);
	}
	else{
		//node = get_waiting_pid(pid);
		node = alloc_wait_list();
		node->pid = pid;
		node->wait_chan_exit = wchan_create((char*) pid);
		add_wait_list(node);
		wchan_lock(node->wait_chan_exit);
		//kprintf("\nputting thread to sleep\n");
		lock_release(wait_lock);
		wchan_sleep(node->wait_chan_exit); /// The current thread is suspended until awakened by someone else
		lock_acquire(wait_lock);
		if(node->status != stat)
		{
			*status = -1;
		}
		else
		{
			*status = stat;
		}

		//kprintf("\nAfter the wake up has happened\n");
	}
	remove_wait_list(node);
	*retval = pid;
	lock_release(wait_lock);
	return 0;
}

/**
* @brief terminate process
*
*	@param[out] code : exite code
*
* @return int \b return 0 on success
*
*/
int sys__exit(int code) {

	pid_t pid = curthread->pid;
	lock_acquire(wait_lock);
	struct wait_List* node;
	//int s;
	(void)code = _MKWAIT_EXIT(code); // generate real exite code with this macro

	node = wait_list;
	while(node != NULL) /// - Is the process in waiting list?
	{
		if(node->pid == pid)
		{
			node->status = code; // the exite code reported back to processes called waitpid()
	        	//wake up all sleeping threads
	        	//splx(s);
	        	wchan_wakeall(node->wait_chan_exit);
		}
		node = node->wl_next;
  }
	if(curthread->pid > 1)
		remove_pid_table(curthread->pid); /// Release process id
	lock_release(wait_lock);
	//kprintf("\n Thread exitted %d\n", curthread->pid);
  	thread_exit(); /// - exit frome process

	return 0;
}

/**
* @brief execute a program
*
*	@param[in]  progname : pointer to char
*	@param[in]  args 		 : pointer  to pointer to char
*	@param[out] retval
*
* @return int \b return 0 on success
*
*/
int
sys_execv(const char *progname, char **args, int *retval)
{
	struct vnode *v;
	vaddr_t entrypoint, stackptr;
	int result;

	if(progname == NULL)
	{
		*retval = -1;
		return EFAULT;
	}

	char *fname = (char *)kmalloc(PATH_MAX);
	size_t size;
	copyinstr((userptr_t)progname,fname,PATH_MAX,&size);

	int i = 0;
	while(args[i] != NULL)
  		i++;
  	int argc = i;

	char **argv;
	argv = (char **)kmalloc(sizeof(char*));

	// Copy in all the argumens in args
	size_t arglen;
	for(i = 0; i < argc; i++) {
		int len = strlen(args[i]);
		len++;
		argv[i]=(char*)kmalloc(len);
		copyinstr((userptr_t)args[i], argv[i], len, &arglen);
  	}
  	//Null terminate argv
  	argv[argc] = NULL;


	/* Open the file. */
	result = vfs_open(fname, O_RDONLY, 0, &v);
	if (result) {
		*retval = -1;
		return result;
	}
	//destroy the address space for a new loadelf
	if(curthread->t_proc->t_addrspace != NULL)
	{
		as_destroy(curthread->t_proc->t_addrspace);
		curthread->t_proc->t_addrspace=NULL;
	}
	/* We should be a new thread. */
	KASSERT(curthread->t_proc->t_addrspace == NULL);

	/* Create a new address space. */
	curthread->t_proc->t_addrspace = as_create();
	if (curthread->t_proc->t_addrspace==NULL) {
		vfs_close(v);
		*retval = -1;
		return ENOMEM;
	}

	/* Activate it. */
	as_activate(curthread->t_proc->t_addrspace);

	/* Load the executable. */
	result = load_elf(v, &entrypoint);
	if (result) {
		/* thread_exit destroys curthread->t_proc->t_addrspace */
		vfs_close(v);
		*retval = -1;
		return result;
	}

	/* Done with the file now. */
	vfs_close(v);

	/* Define the user stack in the address space */
	result = as_define_stack(curthread->t_proc->t_addrspace, &stackptr);
	if (result) {
		/* thread_exit destroys curthread->t_proc->t_addrspace */
		*retval = -1;
		return result;
	}

	//set up the arguments in the user stack



	//copy the parameter to stack
	unsigned int pstack[argc];
  size_t arglen;
	for(i = argc-1; i >= 0; i--) {
		int len = strlen(argv[i]);
		int shift = (len%4);
		if(shift == 0)
			shift = 4;
		stackptr = stackptr - (len + shift);
		copyoutstr(argv[i], (userptr_t)stackptr, len, &arglen);
		pstack[i] = stackptr;
	}

	pstack[argc] = (int)NULL;
	/*save address of each paraeter in stak*/
	for(i = argc-1; i >= 0; i--)
	{
		stackptr = stackptr - 4;
		copyout(&pstack[i] ,(userptr_t)stackptr, sizeof(pstack[i]));
	}
	//kprintf("in execv: %s",(char *)stackptr_ptr+4);
	//null terminate stack
	//int term = 0;
	//memcpy((userptr_t)stackptr_trav, &term, sizeof(term));
	//memcpy((userptr_t)stackptr_ptr, &term, sizeof(term));

	/**
   * @breif DEBUG() is for conditionally printing debug messages to the console.
	*/
	DEBUG(DB_EXEC, "DEBUG EXEC %s", progname);
	//args = pt;
	//copyout(pt,(userptr_t)stackptr,sizeof(pt));

	*retval = 0;
	kfree(argv);
	/* Warp to user mode. */
	enter_new_process(argc /*argc*/, (userptr_t)stackptr /*userspace addr of argv*/,
			  stackptr, entrypoint);

		/* enter_new_process does not return. */
	panic("enter_new_process returned\n");

	return EINVAL;
}

/**
* @brief get the current process ID
*
*	@param[out] retval: pointer to int
*
* @return int
*				/b 0 on success
*
*/
int sys_getpid(int *retval) {
	*retval = (int)curthread->pid;
	return 0;
}
