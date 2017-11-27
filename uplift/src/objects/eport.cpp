#include "stdafx.h"

#include "../runtime.hpp"
#include "eport.hpp"

using namespace uplift;
using namespace uplift::objects;

Eport::Eport(Runtime* runtime)
  : File(runtime)
{
}

Eport::~Eport()
{
}

uint32_t Eport::Close()
{
  return 0;
}

uint32_t Eport::Read(void* data_buffer, size_t data_size, size_t* read_size)
{
  assert_always();
  return 19;
}

uint32_t Eport::Write(const void* data_buffer, size_t data_size, size_t* written_size)
{
  assert_always();
  return 19;
}

uint32_t Eport::IOControl(uint32_t request, void* argp)
{
  assert_always();
  return 19;
}

uint32_t Eport::MMap(void* addr, size_t len, int prot, int flags, off_t offset, void*& allocation)
{
  assert_always();
  return 19;
}
