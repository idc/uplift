#include "stdafx.h"

#include <xenia/base/exception_handler.h>
#include <xenia/base/socket.h>
#include <xenia/base/string.h>

#include "../../xbyak/xbyak/xbyak_util.h"

#include "loader.hpp"
#include "linkable.hpp"

int main(int argc, char* argv[])
{
#ifdef WIN32
  WSADATA wsa_data;
  WSAStartup(MAKEWORD(2, 2), &wsa_data);
#endif

  uplift::Loader loader;

  bool missing_feature = false;
#define CHECK_FEATURE(x,y) \
  if (!loader.cpu_has(Xbyak::util::Cpu::t ## x)) \
  { \
    printf("Your CPU does not support " y ".\n"); \
    missing_feature = true; \
  }
  /* Check necessary CPU features.
   * https://en.wikipedia.org/wiki/Jaguar_(microarchitecture)#Instruction_set_support
   * Not all Jaguar features are actually available, just a subset.
   * Features checks left commented out can be simulated by the loader/runtime, when necessary.
   */
  CHECK_FEATURE(SSE, "SSE");
  CHECK_FEATURE(SSE2, "SSE2");
  CHECK_FEATURE(SSE3, "SSE3");
  CHECK_FEATURE(SSSE3, "SSSE3");
  CHECK_FEATURE(SSE41, "SSE4.1");
  CHECK_FEATURE(SSE42, "SSE4.2");
  CHECK_FEATURE(AESNI, "AES");
  CHECK_FEATURE(AVX, "AVX");
  //CHECK_FEATURE(SSE4a, "SSE4a");
  //CHECK_FEATURE(BMI1, "BMI1");
  CHECK_FEATURE(PCLMULQDQ, "CLMUL");
  CHECK_FEATURE(F16C, "F16C");
  //CHECK_FEATURE(MOVBE, "MOVBE");
#undef CHECK_FEATURE
  if (missing_feature)
  {
    return 1;
  }

  if (argc < 2)
  {
    return 2;
  }

  auto boot_path = xe::to_absolute_path(xe::to_wstring(argv[1]));

  auto base_path = xe::find_base_path(boot_path);
  loader.set_base_path(base_path);

  uplift::Linkable* executable;
  if (!loader.LoadExecutable(xe::find_name_from_path(boot_path), executable))
  {
    return 3;
  }

  std::vector<std::string> args;
  args.push_back("");
  args.push_back("");
  args.push_back("");
  args.push_back("");

  auto handle_exception = [](xe::Exception* ex, void* data)
  {
    return static_cast<uplift::Loader*>(data)->HandleException(ex);
  };
  xe::ExceptionHandler::Install(handle_exception, &loader);
  loader.Run(args);
  xe::ExceptionHandler::Uninstall(handle_exception, &loader);
  return 0;
}
