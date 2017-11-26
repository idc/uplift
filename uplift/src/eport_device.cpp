#include "stdafx.h"

#include "runtime.hpp"
#include "kobject.hpp"
#include "eport_device.hpp"

using namespace uplift;
using namespace uplift::devices;

EportDevice::EportDevice(Runtime* runtime)
  : File(runtime)
{
}

EportDevice::~EportDevice()
{
}

uint32_t EportDevice::Initialize()
{
  return 0;
}

uint32_t EportDevice::Close()
{
  return 0;
}

uint32_t EportDevice::Read(void* data_buffer, size_t data_size, size_t* read_size)
{
  assert_always();
  return 19;
}

uint32_t EportDevice::Write(const void* data_buffer, size_t data_size, size_t* written_size)
{
  assert_always();
  return 19;
}

uint32_t EportDevice::IOControl(uint32_t request, void* argp)
{
  assert_always();
  return 19;
}
