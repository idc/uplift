#pragma once

#include <memory>
#include <vector>

#include <xenia/base/exception_handler.h>

#include <xbyak/xbyak_util.h>

#include "linkable.hpp"
#include "object_table.hpp"
#include "syscalls.hpp"

namespace uplift
{
  class Loader
  {
    friend class SYSCALLS;

  public:
    Loader();
    virtual ~Loader();

    bool cpu_has(Xbyak::util::Cpu::Type type)
    {
      return cpu_.has(type);
    };

    ObjectTable* object_table() { return &object_table_; }

    void* fsbase() const { return fsbase_; }
    void* syscall_handler() const;

    void set_base_path(const std::wstring& base_path)
    {
      base_path_ = base_path;
    }

    bool FindModule(uint32_t id, Linkable*& module);
    bool FindModule(const std::wstring& name, Linkable*& module);
    bool LoadModule(const std::wstring& path, Linkable*& module);
    bool LoadExecutable(const std::wstring& path, Linkable*& executable);

    void Run(std::vector<std::string>& args);

    bool ResolveSymbol(Linkable* skip, uint32_t symbol_name_hash, const std::string& symbol_name, uint64_t& value);

    bool Loader::HandleSyscall(uint64_t id, SyscallReturnValue& result, uint64_t args[6]);
    bool HandleException(xe::Exception* ex);

  private:
    void set_fsbase(void* fsbase);

    bool LoadNeededObjects();
    bool RelocateObjects();

    Xbyak::util::Cpu cpu_;
    ObjectTable object_table_;

    std::wstring base_path_;
    void* fsbase_;
    void* entrypoint_;
    uint8_t* user_stack_base_;
    uint8_t* user_stack_end_;
    std::vector<std::unique_ptr<Linkable>> objects_;
    uint32_t next_module_id_;
    uint32_t next_namedobj_id_;
    SyscallEntry syscall_table_[SyscallTableSize];
  };
}
