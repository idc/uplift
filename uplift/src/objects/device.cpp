#include "stdafx.h"

#include "../runtime.hpp"
#include "device.hpp"

using namespace uplift;
using namespace uplift::objects;

Device::Device(Runtime* runtime)
  : File(runtime)
{
}

Device::~Device()
{
}
