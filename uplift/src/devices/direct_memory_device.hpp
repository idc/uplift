#pragma once

#include "../objects/device.hpp"

namespace uplift::devices
{
  class DirectMemoryDevice : public objects::Device
  {
  public:
    DirectMemoryDevice(Runtime* runtime);
    virtual ~DirectMemoryDevice();

    SyscallError Initialize(std::string path, uint32_t flags, uint32_t mode);
    SyscallError Close();

    SyscallError Read(void* data_buffer, size_t data_size, size_t* read_size);
    SyscallError Write(const void* data_buffer, size_t data_size, size_t* written_size);
    SyscallError IOControl(uint32_t request, void* argp);
    SyscallError MMap(void* addr, size_t len, int prot, int flags, off_t offset, void*& allocation);
  };
}
