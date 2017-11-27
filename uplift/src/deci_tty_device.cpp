#include "stdafx.h"

#include "runtime.hpp"
#include "kobject.hpp"
#include "deci_tty_device.hpp"

using namespace uplift;
using namespace uplift::devices;

DeciTTYDevice::DeciTTYDevice(Runtime* runtime)
  : File(runtime)
{
}

DeciTTYDevice::~DeciTTYDevice()
{
}

uint32_t DeciTTYDevice::Initialize()
{
  return 0;
}

uint32_t DeciTTYDevice::Close()
{
  return 0;
}

uint32_t DeciTTYDevice::Read(void* data_buffer, size_t data_size, size_t* read_size)
{
  assert_always();
  return 19;
}

uint32_t DeciTTYDevice::Write(const void* data_buffer, size_t data_size, size_t* written_size)
{
  assert_always();
  return 19;
}

uint32_t DeciTTYDevice::IOControl(uint32_t request, void* argp)
{
  assert_always();
  return 19;
}

uint32_t DeciTTYDevice::MMap(void* addr, size_t len, int prot, int flags, off_t offset, void*& allocation)
{
  assert_always();
  return 19;
}
