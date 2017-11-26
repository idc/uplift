#include "stdafx.h"

#include "runtime.hpp"
#include "ksocket.hpp"

#ifdef XE_PLATFORM_WIN32
#include "xenia/base/platform_win.h"
#include <WS2tcpip.h>
#include <WinSock2.h>
#else
#error todo
#endif

using namespace uplift;
using namespace uplift::objects;

using Domain = Socket::Domain;
using Type = Socket::Type;
using Protocol = Socket::Protocol;

struct native_dtp
{
  int af;
  int type;
  int protocol;
};

bool translate_dtp(Domain domain, Type type, Protocol protocol, native_dtp& native_dtp)
{
  switch (domain)
  {
    case Domain::IPv4:
    {
      switch (type)
      {
        case Type::Datagram:
        case Type::DatagramP2P:
        {
          switch (protocol)
          {
            case Protocol::Default:
            {
               native_dtp = { AF_INET, SOCK_DGRAM, IPPROTO_UDP };
               return true;
            }
          }
        }
      }
    }
  }
  return false;
}

Socket::Socket(Runtime* runtime)
  : File(runtime)
  , native_handle_(-1)
  , domain_(Domain::Invalid)
  , type_(Type::Invalid)
  , protocol_(Protocol::Invalid)
{
}

Socket::Socket(Runtime* runtime, uint32_t native_handle)
  : File(runtime)
  , native_handle_(native_handle) 
{
}

Socket::~Socket()
{
  Close(); 
}

uint32_t Socket::Initialize(Domain domain, Type type, Protocol protocol)
{
  domain_ = domain;
  type_ = type;
  protocol_ = protocol;

  native_dtp native_dtp;
  if (!translate_dtp(domain, type, protocol, native_dtp))
  {
    return 22;
  }

  native_handle_ = socket(native_dtp.af, native_dtp.type, native_dtp.protocol);
  return native_handle_ == -1 ? -1 : 0;
}

uint32_t Socket::Close()
{
#if XE_PLATFORM_WIN32
  int result = closesocket(native_handle_);
#elif XE_PLATFORM_LINUX
  int result = close(native_handle_);
#endif
  return result != 0 ? -1 : 0;
}

uint32_t Socket::Read(void* data_buffer, size_t data_size, size_t* read_size)
{
  assert_always();
  return 19;
}

uint32_t Socket::Write(const void* data_buffer, size_t data_size, size_t* written_size)
{
  assert_always();
  return 19;
}

uint32_t Socket::IOControl(uint32_t request, void* argp)
{
  switch (request)
  {
    case 0x802450C9: // init?
    {
      return 0;
    }
  }

  assert_always();
  return -1;
}
