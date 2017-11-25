#include "stdafx.h"

#include "loader.hpp"
#include "kobject.hpp"
#include "dipsw_device.hpp"

using namespace uplift;
using namespace uplift::devices;

DipswDevice::DipswDevice(Loader* loader)
  : Object(loader, ObjectType)
{
}

DipswDevice::~DipswDevice()
{
}

uint32_t DipswDevice::Initialize()
{
  return 0;
}

uint32_t DipswDevice::Close()
{
  return 0;
}

uint32_t DipswDevice::Read(void* data_buffer, size_t data_size, size_t* read_size)
{
  assert_always();
  return 19;
}

uint32_t DipswDevice::Write(const void* data_buffer, size_t data_size, size_t* written_size)
{
  assert_always();
  return 19;
}

uint32_t DipswDevice::IOControl(uint32_t request, void* argp)
{
  switch (request)
  {
    case 0x40048806:
    {
      *static_cast<uint32_t*>(argp) = 1;
      return 0;
    }
    case 0x40048807:
    {
      *static_cast<uint32_t*>(argp) = 0;
      return 0;
    }
    case 0x40088808:
    {
      *static_cast<uint64_t*>(argp) = 0;
      return 0;
    }
  }
  assert_always();
  return 22;
}
