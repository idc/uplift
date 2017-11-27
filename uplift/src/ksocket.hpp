#pragma once

#include "kobject.hpp"
#include "kfile.hpp"

namespace uplift
{
  class Loader;
}

namespace uplift::objects
{
  class Socket : public File
  {
  public:
    enum class Domain : int32_t
    {
      Invalid = -1,
      IPv4 = 2,
    };

    enum class Type : int32_t
    {
      Invalid = -1,
      Stream = 1,
      Datagram = 2,
      DatagramP2P = 6,
    };

    enum class Protocol : int32_t
    {
      Invalid = -1,
      Default = 0,
      TCP = 6,
      UDP = 17,
    };

    Socket(Runtime* runtime);
    ~Socket();

    uint64_t native_handle() const { return native_handle_; }

    uint32_t Initialize(Domain domain, Type type, Protocol protocol);
    uint32_t Close();

    uint32_t Read(void* data_buffer, size_t data_size, size_t* read_size);
    uint32_t Write(const void* data_buffer, size_t data_size, size_t* written_size);
    uint32_t IOControl(uint32_t request, void* argp);
    uint32_t MMap(void* addr, size_t len, int prot, int flags, off_t offset, void*& allocation);

  private:
    Socket(Runtime* runtime, uint32_t native_handle);
    uint64_t native_handle_ = -1;

    Domain domain_;
    Type type_;
    Protocol protocol_;
  };
}
