#pragma once

#include "kobject.hpp"
#include "kfile.hpp"

namespace uplift
{
  class Loader;
}

namespace uplift::devices
{
  class ConsoleDevice : public objects::File
  {
  public:
    ConsoleDevice(Runtime* runtime);
    ~ConsoleDevice();

    uint32_t Initialize();
    uint32_t Close();

    uint32_t Read(void* data_buffer, size_t data_size, size_t* read_size);
    uint32_t Write(const void* data_buffer, size_t data_size, size_t* written_size);
    uint32_t IOControl(uint32_t request, void* argp);
  };
}
