#pragma once

namespace uplift
{
  union SyscallReturnValue
  {
    void* ptr;
    uint64_t val;
  };

  typedef bool(*SYSCALL_HANDLER)(Loader* loader, SyscallReturnValue& retval, ...);

  class SYSCALLS
  {
  private:
    SYSCALLS() {}
  public:
#define SYSCALL(x, y, ...) static bool y(Loader* loader, SyscallReturnValue&, __VA_ARGS__)
#include "syscall_table.inl"
#undef SYSCALL
  };

  class Loader;

  struct SyscallEntry
  {
    void* handler;
    const char* name;
  };

  const size_t SyscallTableSize = 1024;
  void get_syscall_table(SyscallEntry table[SyscallTableSize]);
}
