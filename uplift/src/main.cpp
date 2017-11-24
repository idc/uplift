#include "stdafx.h"

#include <xenia/base/exception_handler.h>
#include <xenia/base/string.h>

#include "loader.hpp"
#include "linkable.hpp"

bool loader_handle_exception(xe::Exception* ex, void* data)
{
  return static_cast<uplift::Loader*>(data)->HandleException(ex);
}

int main(int argc, char* argv[])
{
  if (argc < 2)
  {
    return 1;
  }

  auto eboot_path = xe::to_absolute_path(xe::to_wstring(argv[1]));
  auto base_path = xe::find_base_path(eboot_path);

  uplift::Loader loader(base_path);
  uplift::Linkable* executable;
  if (!loader.LoadExecutable(xe::find_name_from_path(eboot_path), executable))
  {
    return 1;
  }

  std::vector<std::string> args;
  args.push_back("");
  args.push_back("");
  args.push_back("");
  args.push_back("");

  xe::ExceptionHandler::Install(loader_handle_exception, &loader);
  loader.Run(args);
  xe::ExceptionHandler::Uninstall(loader_handle_exception, &loader);
  return 0;
}
