#pragma once

#include "object.hpp"

namespace uplift::objects
{
  class File : public Object
  {
  public:
    static const Object::Type ObjectType = Type::File;

  protected:
    File(Runtime* runtime);

  public:
    virtual ~File();

    virtual SyscallError Close() = 0;

    virtual SyscallError Read(void* data_buffer, size_t data_size, size_t* read_size) = 0;
    virtual SyscallError Write(const void* data_buffer, size_t data_size, size_t* written_size) = 0;
    virtual SyscallError IOControl(uint32_t request, void* argp) = 0;
    virtual SyscallError MMap(void* addr, size_t len, int prot, int flags, off_t offset, void*& allocation) = 0;
  };
}
