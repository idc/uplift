#include "stdafx.h"

#include "../runtime.hpp"
#include "../syscall_errors.hpp"
#include "direct_memory_device.hpp"

using namespace uplift;
using namespace uplift::devices;
using namespace uplift::syscall_errors;

DirectMemoryDevice::DirectMemoryDevice(Runtime* runtime)
  : Device(runtime)
{
}

DirectMemoryDevice::~DirectMemoryDevice()
{
}

SCERR DirectMemoryDevice::Initialize(std::string path, uint32_t flags, uint32_t mode)
{
  return SUCCESS;
}

SCERR DirectMemoryDevice::Close()
{
  return SUCCESS;
}

SCERR DirectMemoryDevice::Read(void* data_buffer, size_t data_size, size_t* read_size)
{
  assert_always();
  return SCERR::eNOSYS;
}

SCERR DirectMemoryDevice::Write(const void* data_buffer, size_t data_size, size_t* written_size)
{
  assert_always();
  return SCERR::eNOSYS;
}

SCERR DirectMemoryDevice::IOControl(uint32_t request, void* argp)
{
  assert_always();
  return SCERR::eNOSYS;
}

SCERR DirectMemoryDevice::MMap(void* addr, size_t len, int prot, int flags, off_t offset, void*& allocation)
{
  assert_always();
  return SCERR::eNOSYS;
}
