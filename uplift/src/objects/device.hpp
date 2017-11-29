#pragma once

#include "file.hpp"

namespace uplift::objects
{
  class Device : public File
  {
  protected:
    Device(Runtime* runtime);

  public:
    virtual ~Device();

    virtual SyscallError Initialize(std::string path, uint32_t flags, uint32_t mode) = 0;
  };
}
