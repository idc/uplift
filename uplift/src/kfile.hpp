#pragma once

#include "kobject.hpp"

namespace uplift
{
  class Loader;
}

namespace uplift::objects
{
  class File : public Object
  {
  public:
    static const Object::Type ObjectType = Type::File;

    File(Runtime* runtime);
    ~File();

    virtual uint32_t Close() = 0;

    virtual uint32_t Read(void* data_buffer, size_t data_size, size_t* read_size) = 0;
    virtual uint32_t Write(const void* data_buffer, size_t data_size, size_t* written_size) = 0;
    virtual uint32_t IOControl(uint32_t request, void* argp) = 0;
  };
}
