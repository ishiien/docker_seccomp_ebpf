#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/fcntl.h>
#include <syscall.h>

void die (const char *msg)
{
  perror(msg);
  exit(errno);
}

int syscall_number_to_string(int syscall_number,char *syscall_string){
    char arg_number[20];
    char command[10] = "ausyscall";
    char space[2] = " ";
    int result;

    sprintf(arg_number,"%d",syscall_number);
    strcat(command,space);
    strcat(command,arg_number);
    result = system(command);
    sprintf(syscall_string,"%d",result);

    return *syscall_string;
}

int main(int argc, char *argv[])
{
  int pid, result;
  struct user_regs_struct regs;
  const char *prog;

  if (argc < 2) {
    printf("usage: \n%s PROG [ARG]\n", argv[0]);
    return 0;
  }

  prog = argv[1];

  switch( (pid = fork()) ) {
    case -1:  die("Failed fork");
    case 0:
              // 親プロセスにトレースさせる
              ptrace(PTRACE_TRACEME, 0, NULL, NULL);
              result = execvp(prog, &argv[1]);
              if (result) {
                die("execvp");
                return result;
              }
              return 0;
  }

  while(1) {
    int st;
    // 子プロセスを再開する
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

    char syscall_string [20];
    char sys_str[20];
    *sys_str = syscall_number_to_string(regs.orig_rax,&syscall_string);

    printf("%s = %lld\n", *sys_str, regs.orig_rax);
  }
  return 0;
}