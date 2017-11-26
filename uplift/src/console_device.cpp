#include "stdafx.h"

#include "runtime.hpp"
#include "kobject.hpp"
#include "console_device.hpp"

using namespace uplift;
using namespace uplift::devices;

ConsoleDevice::ConsoleDevice(Runtime* runtime)
  : File(runtime)
{
}

ConsoleDevice::~ConsoleDevice()
{
}

uint32_t ConsoleDevice::Initialize()
{
  return 0;
}

uint32_t ConsoleDevice::Close()
{
  return 0;
}

uint32_t ConsoleDevice::Read(void* data_buffer, size_t data_size, size_t* read_size)
{
  assert_always();
  return 19;
}

uint32_t ConsoleDevice::Write(const void* data_buffer, size_t data_size, size_t* written_size)
{
  assert_always();
  return 19;
}

uint32_t ConsoleDevice::IOControl(uint32_t request, void* argp)
{
  assert_always();
  return 19;
}
