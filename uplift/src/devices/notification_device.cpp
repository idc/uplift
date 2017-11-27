#include "stdafx.h"

#include "../runtime.hpp"
#include "notification_device.hpp"

using namespace uplift;
using namespace uplift::devices;

NotificationDevice::NotificationDevice(Runtime* runtime)
  : Device(runtime)
{
}

NotificationDevice::~NotificationDevice()
{
}

uint32_t NotificationDevice::Initialize(std::string path, uint32_t flags, uint32_t mode)
{
  return 0;
}

uint32_t NotificationDevice::Close()
{
  return 0;
}

uint32_t NotificationDevice::Read(void* data_buffer, size_t data_size, size_t* read_size)
{
  assert_always();
  return 19;
}

uint32_t NotificationDevice::Write(const void* data_buffer, size_t data_size, size_t* written_size)
{
  if (data_size > 0x28)
  {
    printf("NOTIFICATION: %s\n", &static_cast<const char*>(data_buffer)[0x28]);
  }

  if (written_size)
  {
    *written_size = data_size;
  }

  return 0;
}

uint32_t NotificationDevice::IOControl(uint32_t request, void* argp)
{
  assert_always();
  return 19;
}

uint32_t NotificationDevice::MMap(void* addr, size_t len, int prot, int flags, off_t offset, void*& allocation)
{
  assert_always();
  return 19;
}
