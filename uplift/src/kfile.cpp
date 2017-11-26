#include "stdafx.h"

#include "runtime.hpp"
#include "kobject.hpp"
#include "kfile.hpp"

using namespace uplift;
using namespace uplift::objects;

File::File(Runtime* runtime)
  : Object(runtime, ObjectType)
{
}

File::~File()
{
}
