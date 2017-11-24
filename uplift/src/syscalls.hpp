#pragma once

namespace uplift
{
  class SYSCALLS
  {
  private:
    SYSCALLS() {}
  public:
#define SYSCALL(x, y, ...) static bool y(Loader* loader, uint64_t*, __VA_ARGS__)
#include "syscall_table.inl"
#undef SYSCALL
  };

  class Loader;
  typedef bool(*SYSCALL_HANDLER)(Loader* loader, uint64_t* retval, ...);

  struct SyscallEntry
  {
    void* handler;
    const char* name;
  };
  void get_syscall_table(SyscallEntry table[1024]);
}
