#include "stdafx.h"

#include <queue>

#include <intrin.h>

#include <xenia/base/exception_handler.h>
#include <xenia/base/memory.h>
#include <xenia/base/string.h>
#include <xenia/base/x64_context.h>

#include "../../capstone/include/capstone.h"
#include "../../capstone/include/x86.h"

#include "../../xbyak/xbyak/xbyak.h"

#include "loader.hpp"
#include "linkable.hpp"
#include "syscalls.hpp"
#include "bmi1.hpp"

using namespace uplift;

Loader::Loader()
  : cpu_()
  , object_table_()
  , base_path_()
  , fsbase_(0)
  , entrypoint_(nullptr)
  , user_stack_base_(nullptr)
  , user_stack_end_(nullptr)
  , next_module_id_(0)
  , next_namedobj_id_(0)
{
  std::memset(syscall_table_, 0, sizeof(syscall_table_));
  get_syscall_table(syscall_table_);
}

Loader::~Loader()
{
  if (user_stack_base_ != nullptr)
  {
    xe::memory::DeallocFixed(user_stack_base_, 0, xe::memory::DeallocationType::kRelease);
    user_stack_base_ = nullptr;
  }
}

bool Loader::FindModule(uint32_t id, Linkable*& module)
{
  auto const& it = std::find_if(objects_.begin(), objects_.end(), [&](std::unique_ptr<Linkable>& l) { return l->id() == id; });
  if (it != objects_.end())
  {
    module = (*it).get();
    return true;
  }

  return false;
}

bool Loader::FindModule(const std::wstring& path, Linkable*& module)
{
  auto name = xe::find_name_from_path(path);

  auto const& it = std::find_if(objects_.begin(), objects_.end(), [&](std::unique_ptr<Linkable>& l) { return l->name() == name; });
  if (it != objects_.end())
  {
    module = (*it).get();
    return true;
  }

  return false;
}

bool Loader::LoadModule(const std::wstring& path, Linkable*& module)
{
  if (objects_.size() <= 0)
  {
    return false;
  }

  auto name = xe::find_name_from_path(path);

  if (FindModule(name, module))
  {
    return true;
  }

  auto linkable = uplift::Linkable::Load(this, xe::join_paths(base_path_, path));
  if (linkable == nullptr)
  {
    auto system_path = xe::join_paths(base_path_, L"uplift_sys");
    linkable = uplift::Linkable::Load(this, xe::join_paths(system_path, path));
    if (linkable == nullptr)
    {
      return false;
    }
  }

  module = linkable.get();
  objects_.push_back(std::move(linkable));
  module->set_id(++next_module_id_);
  return true;
}

bool Loader::LoadExecutable(const std::wstring& path, Linkable*& eboot)
{
  auto linkable = Linkable::Load(this, xe::join_paths(base_path_, path));
  if (linkable == nullptr)
  {
    return false;
  }

  eboot = linkable.get();
  objects_.push_back(std::move(linkable));

  eboot->set_id(++next_module_id_);

  void* entrypoint;
  if (!eboot->has_dynamic())
  {
    entrypoint = eboot->entrypoint();
  }
  else
  {
    Linkable* libkernel;
    if (!LoadModule(L"libkernel.prx", libkernel))
    {
      printf("COULD NOT PRELOAD libkernel!\n");
      objects_.clear();
      return false;
    }

    Linkable* libc;
    if (!LoadModule(L"libSceLibcInternal.prx", libc))
    {
      printf("COULD NOT PRELOAD libSceLibcInternal!\n");
      objects_.clear();
      return false;
    }

    entrypoint = libkernel->entrypoint();
  }

  entrypoint_ = entrypoint;
  return true;
}

class EntrypointTrampolineGenerator : public Xbyak::CodeGenerator
{
public:
  EntrypointTrampolineGenerator(void* target)
  {
    push(rbp);
    mov(rbp, rsp);
    push(r12); push(r13); push(r14); push(r15);
    push(rdi); push(rsi); push(rbx);

    sub(rsp, 8);

    mov(rdi, rcx);
    mov(rax, (size_t)target);

    call(rax);

    add(rsp, 8);

    pop(rbx); pop(rsi); pop(rdi);
    pop(r15); pop(r14); pop(r13); pop(r12);
    pop(rbp);
    ret();
  }
};

void Loader::Run(std::vector<std::string>& args)
{
  const size_t user_stack_size = 20 * 1024 * 1024;
  user_stack_base_ = static_cast<uint8_t*>(xe::memory::AllocFixed(
    0, user_stack_size, xe::memory::AllocationType::kReserve, xe::memory::PageAccess::kNoAccess));
  user_stack_end_ = &user_stack_base_[user_stack_size];

  printf("user stack: %p-%p\n", user_stack_base_, user_stack_end_ - 1);

  auto eboot = (*objects_.begin()).get();

  EntrypointTrampolineGenerator trampoline(entrypoint_);
  auto func = trampoline.getCode<void*(*)(void*)>();

  union stack_entry
  {
    const void* ptr;
    uint64_t val;
  }
  stack[128];
  stack[0].val = 1 + args.size(); // argc
  auto s = reinterpret_cast<stack_entry*>(&stack[1]);
  (*s++).ptr = eboot->name().c_str();
  for (auto it = args.begin(); it != args.end(); ++it)
  {
    (*s++).ptr = (*it).c_str();
  }
  (*s++).ptr = nullptr; // arg null terminator
  (*s++).ptr = nullptr; // env null terminator
  (*s++).val = 9ull; // entrypoint type
  (*s++).ptr = eboot->entrypoint();
  (*s++).ptr = nullptr; // aux null type
  (*s++).ptr = nullptr;
  
  func(stack);
}

bool Loader::ResolveSymbol(Linkable* skip, uint32_t symbol_name_hash, const std::string& symbol_name, uint64_t& value)
{
  for (auto it = objects_.begin(); it != objects_.end(); ++it)
  {
    if (skip != nullptr && (*it).get() == skip)
    {
      continue;
    }
    if ((*it)->ResolveSymbol(symbol_name_hash, symbol_name, value))
    {
      return true;
    }
  }
  return false;
}

bool Loader::HandleException(xe::Exception* ex)
{
  if (ex->code() != xe::Exception::Code::kIllegalInstruction)
  {
    return false;
  }

  auto target = reinterpret_cast<uint8_t*>(ex->pc());

  auto instruction_bytes = xe::load_and_swap<uint16_t>(target);
  if (instruction_bytes == 0x0F0B)
  {
    return false;
  }
  else
  {
    auto thread_context = ex->thread_context();
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
      assert_always();
      return false;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    auto insn = cs_malloc(handle);
    const uint8_t* code = target;
    size_t code_size = 15;
    uint64_t address = ex->pc();
    bool result = false;
    if (cs_disasm_iter(handle, &code, &code_size, &address, insn))
    {
      if (insn->id == X86_INS_ANDN)
      {
        simulate_andn(insn, thread_context);
        result = true;
      }
      else if (insn->id == X86_INS_BLSI)
      {
        simulate_blsi(insn, thread_context);
        result = true;
      }
      else if (insn->id == X86_INS_BEXTR)
      {
        simulate_bextr(insn, thread_context);
        result = true;
      }
    }
    cs_free(insn, 1);
    cs_close(&handle);
    return result;
  }

  return false;
}

bool syscall_dispatch_trampoline(
  Loader* loader, uint64_t id,
  uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6,
  SyscallReturnValue& result)
{
  uint64_t args[6];
  args[0] = arg1;
  args[1] = arg2;
  args[2] = arg3;
  args[3] = arg4;
  args[4] = arg5;
  args[5] = arg6;
  return loader->HandleSyscall(id, result, args);
}

void* Loader::syscall_handler() const
{
  return syscall_dispatch_trampoline;
}

bool Loader::HandleSyscall(uint64_t id, SyscallReturnValue& result, uint64_t args[6])
{
  if (id >= _countof(syscall_table_) || syscall_table_[id].handler == nullptr)
  {
    printf("UNKNOWN SYSCALL: %I64u\n", id);
    result.val = -1;
    assert_always();
    return false;
  }
  if (id != 4) printf("SYSCALL(%03I64d): %s\n", id, syscall_table_[id].name);
  return static_cast<SYSCALL_HANDLER>(syscall_table_[id].handler)(this, result, args[0], args[1], args[2], args[3], args[4], args[5]);
}

void Loader::set_fsbase(void* fsbase)
{
  fsbase_ = fsbase;
  for (auto it = objects_.begin(); it != objects_.end(); ++it)
  {
    (*it)->set_fsbase(fsbase);
  }
}

bool Loader::LoadNeededObjects()
{
  printf("LOADING NEEDED OBJECTS\n");

  std::queue<Linkable*> queue;
  for (auto it = objects_.begin(); it != objects_.end(); ++it)
  {
    queue.push((*it).get());
  }

  while (queue.size() > 0)
  {
    auto linkable = queue.front();
    queue.pop();

    auto shared_object_names = linkable->dynamic_info().shared_object_names;
    for (auto it = shared_object_names.begin(); it != shared_object_names.end(); ++it)
    {
      const auto& shared_object_name = *it;
      Linkable* dummy;
      if (FindModule(xe::to_wstring(shared_object_name), dummy))
      {
        continue;
      }

      if (!LoadModule(xe::to_wstring(shared_object_name), dummy))
      {
        printf("Failed to preload needed '%s'.\n", shared_object_name.c_str());
        continue;
      }

      queue.push(dummy);
    }
  }

  return true;
}

bool Loader::RelocateObjects()
{
  printf("RELOCATING OBJECTS\n");
  for (auto it = objects_.begin(); it != objects_.end(); ++it)
  {
    if (!(*it)->Relocate())
    {
      return false;
    }
  }
  return true;
}
