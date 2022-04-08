#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/palloc.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void check_addr(void *addr);
/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

void check_addr(void *addr)
{
	if (addr == NULL || is_kernel_vaddr(addr) || pml4_get_page(thread_current()->pml4, addr))
	{
		exit(-1);
	}
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	// TODO: Your implementation goes here.
	printf("system call!\n");
	switch (f->R.rax)
	{ // rax is the system call number
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	// case SYS_FORK:
	// 	f->R.rax = fork(f->R.rdi /*,f*/);
	// 	break;
	case SYS_EXEC:
		if (exec(f->R.rdi) == -1)
		{
			exit(-1);
		}
		break;
	case SYS_WAIT:
		f->R.rax = process_wait(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	default:
		exit(-1);
		break;
	}
	thread_exit();
}

void halt(void)
{
	power_off();
}

void exit(int status)
{
	struct thread *t = thread_current();
	t->exit = status;
	thread_exit();
}

 tid_t fork(const char *thread_name)
 {
 }

/*Change current process to the executable whose name is given in cmd_line,
passing any given arguments. This never returns if successful.
Otherwise the process terminates with exit state -1, if the program cannot load or run for any reason.
This function does not change the name of the thread that called exec.
Please note that file descriptors remain open across an exec call.*/
int exec(const char *cmd_line)
{
	check_addr(cmd_line);
	/*uint8_t *ptr = palloc_get_page(0);*/
	if (process_exec(cmd_line) < 0)
	{
		return -1;
	}
}

int wait(tid_t tid)
{
	returnprocess_wait(tid);
	/*child list를 thread 구조체 내에 만들어서 관리 및 tid로 child 접근*/
}

bool create(const char *file, unsigned initial_size)
{
	check_addr(file);
	return filesys_create(file, initial_size);
}

bool remove(const char *file)
{
	check_addr(file);
	return filesys_remove(file);
}

int open(const char *file)
{
	check_addr(file);
	struct file *opened_file = filesys_open(file);
	if (file == NULL)
	{
		return -1;
	}
	struct thread *curr = thread_current();
	curr->file_dscp_cnt++;
	int fd = curr->file_dscp_cnt;
	curr->file_dscp_table[fd] = opened_file;
	return fd;
}

int filesize(int fd)
{
	struct thread *curr = thread_current();
	if (fd <= (curr->file_dscp_cnt))
	{
		if (fd > 1)
		{
			return (int)file_length(curr->file_dscp_table[fd]);
		}
	}
}

int read(int fd, void *buffer, unsigned size)
{
	struct thread *curr = thread_current();
	if (fd <= (curr->file_dscp_cnt))
	{
		struct file *file = curr->file_dscp_table[fd];
		if (fd == 0)
		{
			int i;
			for (i = 0; i < size; i++)
			{
				if (input_getc() == 0)
					return i;
			}
			return size;
		}
		if (fd > 1)
		{
			return file_read(file, buffer, size);
		}
	}
}

int write(int fd, const void *buffer, unsigned size)
{
	struct thread *curr = thread_current();
	if (fd <= (curr->file_dscp_cnt))
	{
		struct file *file = curr->file_dscp_table[fd];
		if (fd == 1)
		{
			enum intr_level old_level;
			old_level = intr_disable();
			putbuf(buffer,size);
			intr_set_level(old_level);
		}
		if (fd > 1)
		{
			struct file *file = curr->file_dscp_table[fd];
			off_t bytes;
			while(!(bytes = file_write(file,buffer,size))){
				if(!(file->inode->deny_write_cnt))
					return 0;
			}
			return bytes;
		}
	}
}

void seek(int fd, unsigned position)
{
	struct thread *curr = thread_current();
	if (fd <= (curr->file_dscp_cnt))
	{
		if (fd > 1)
		{
			struct file *target = curr->file_dscp_table[fd];
			target->pos = position;
		}
	}
}

unsigned tell(int fd)
{
	if (fd <= (curr->file_dscp_cnt))
	{
		if (fd > 1)
		{
			struct thread *curr = thread_current();
			struct file *file = curr->file_dscp_table[fd];
			return file_tell(file);
		}
	}
}

void close(int fd)
{
	if (fd <= (curr->file_dscp_cnt))
	{
		if (fd > 1)
		{
			struct thread *curr = thread_current();
			struct file *file = curr->file_dscp_table[fd];
			if (file == NULL)
			{
				return;
			}
			file_close(file);
			curr->file_dscp_table[fd] = NULL;
			curr->file_dscp_cnt--;
		}
	}
}