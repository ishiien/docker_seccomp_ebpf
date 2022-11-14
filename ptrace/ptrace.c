#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include <sys/syscall.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <syscall.h>


void die (const char *msg)
{
  perror(msg);
  exit(errno);
}

int syscall_number_to_string(int syscall_number){
    char arg_number[20];
    char command[20] = "ausyscall";
    char space[2] = " ";
    int result;

    sprintf(arg_number,"%d",syscall_number);
    strcat(command,space);
    strcat(command,arg_number);
    result = system(command);
    printf("%d",result);
    return result;
}

int main(int argc, char *argv[])
{
  int status;
  int pid;
  struct user_regs_struct regs;

  if (argc < 2) {
    printf("please set pid\n");
    exit(1);
  }

  pid = atoi(argv[1]);
  printf("attach to %d\n", pid);

  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
    perror("failed to attach");
    exit(1);
  }

  while (1) {
    int st;
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    if (waitpid(pid, &st, __WALL) == -1) {
      break;
    }

    if (!(WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP)) {
      break;
    }

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    if (regs.rax == - ENOSYS) {
      continue;
    }

    int syscall_string;
    syscall_string = syscall_number_to_string(regs.orig_rax);

  }

  return 0;
}