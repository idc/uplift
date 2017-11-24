#pragma once

#include <memory>
#include <vector>

#include <xenia/base/exception_handler.h>

#include "linkable.hpp"
#include "syscalls.hpp"

namespace uplift
{
  class Loader
  {
    friend class SYSCALLS;

  public:
    Loader(const std::wstring& base_path);
    virtual ~Loader();

    void* fsbase() const { return fsbase_; }
    void* syscall_handler() const;

    bool FindModule(uint32_t id, Linkable*& module);
    bool FindModule(const std::wstring& name, Linkable*& module);
    bool LoadModule(const std::wstring& path, Linkable*& module);
    bool LoadExecutable(const std::wstring& path, Linkable*& executable);

    void Run(std::vector<std::string>& args);

    bool ResolveSymbol(Linkable* skip, uint32_t symbol_name_hash, const std::string& symbol_name, uint64_t& value);

    bool Loader::HandleSyscall(uint64_t id, uint64_t* result, uint64_t args[6]);
    bool HandleException(xe::Exception* ex);

  private:
    void set_fsbase(void* fsbase);

    bool LoadNeededObjects();
    bool RelocateObjects();

    std::wstring base_path_;
    void* fsbase_;
    void* entrypoint_;
    uint8_t* user_stack_base_;
    uint8_t* user_stack_end_;
    std::vector<std::unique_ptr<Linkable>> objects_;
    uint32_t next_module_id_;
    uint32_t next_namedobj_id_;
    SyscallEntry syscall_table_[1024];
  };
}
