#include "stdafx.h"

#include "../runtime.hpp"
#include "dipsw_device.hpp"

using namespace uplift;
using namespace uplift::devices;

DipswDevice::DipswDevice(Runtime* runtime)
  : Device(runtime)
{
}

DipswDevice::~DipswDevice()
{
}

uint32_t DipswDevice::Initialize(std::string path, uint32_t flags, uint32_t mode)
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

    case 0x40088809:
    {
      *static_cast<uint64_t*>(argp) = 0;
      return 0;
    }
  }
  assert_always();
  return 22;
}

uint32_t DipswDevice::MMap(void* addr, size_t len, int prot, int flags, off_t offset, void*& allocation)
{
  assert_always();
  return 19;
}
