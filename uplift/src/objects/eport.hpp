#pragma once

#include "file.hpp"

namespace uplift::objects
{
  class Eport : public File
  {
  public:
    Eport(Runtime* runtime);
    virtual ~Eport();

    SyscallError Close();

    SyscallError Read(void* data_buffer, size_t data_size, size_t* read_size);
    SyscallError Write(const void* data_buffer, size_t data_size, size_t* written_size);
    SyscallError IOControl(uint32_t request, void* argp);
    SyscallError MMap(void* addr, size_t len, int prot, int flags, off_t offset, void*& allocation);
  };
}
