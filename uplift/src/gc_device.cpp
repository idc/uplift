#include "stdafx.h"

#include "runtime.hpp"
#include "kobject.hpp"
#include "gc_device.hpp"

using namespace uplift;
using namespace uplift::devices;

GCDevice::GCDevice(Runtime* runtime)
  : File(runtime)
{
}

GCDevice::~GCDevice()
{
}

uint32_t GCDevice::Initialize()
{
  return 0;
}

uint32_t GCDevice::Close()
{
  return 0;
}

uint32_t GCDevice::Read(void* data_buffer, size_t data_size, size_t* read_size)
{
  assert_always();
  return 19;
}

uint32_t GCDevice::Write(const void* data_buffer, size_t data_size, size_t* written_size)
{
  assert_always();
  return 19;
}

uint32_t GCDevice::IOControl(uint32_t request, void* argp)
{
  assert_always();
  return 19;
}

uint32_t GCDevice::MMap(void* addr, size_t len, int prot, int flags, off_t offset, void*& allocation)
{
  assert_always();
  return 19;
}
