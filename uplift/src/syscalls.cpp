#include "stdafx.h"

#include <xenia/base/memory.h>
#include <xenia/base/string.h>

#include "loader.hpp"
#include "syscalls.hpp"
#include "helpers.hpp"

using namespace uplift;

bool SYSCALLS::write(Loader* loader, uint64_t* retval, int fd, const void* buf, size_t nbytes)
{
  if (fd == 1 || fd == 2)
  {
    auto b = static_cast<const char*>(buf);
    for (size_t i = 0; i < nbytes; ++i, ++b)
    {
      printf("%c", *b);
    }
    *retval = nbytes;
    return true;
  }
  else if (fd == 0x0BEEF002)
  {
    printf("NOTIFICATION: %s\n", &static_cast<const char*>(buf)[0x28]);
    *retval = nbytes;
    return true;
  }

  *retval = -1;
  assert_always();
  return false;
}

bool SYSCALLS::open(Loader* loader, uint64_t* retval, const char* cpath, int flags, uint64_t mode)
{
  printf("open: %s, %x, %I64d\n", cpath, flags, mode);

  auto path = std::string(cpath);

  if (path == "/dev/dipsw")
  {
    *retval = 0x0BEEF001u;
    return true;
  }
  else if (path == "/dev/notification0")
  {
    *retval = 0x0BEEF002u;
    return true;
  }
  else if (path == "/dev/notification1")
  {
    *retval = 0x0BEEF003u;
    return true;
  }

  assert_always();
  *retval = -1;
  return false;
}

bool SYSCALLS::close(Loader* loader, uint64_t* retval, int fd)
{
  if (fd == 0x0BEEF001)
  {
    *retval = 0;
    return true;
  }

  assert_always();
  *retval = -1;
  return false;
}

bool SYSCALLS::getpid(Loader* loader, uint64_t* retval)
{
  *retval = 123;
  return true;
}

bool SYSCALLS::ioctl(Loader* loader, uint64_t* retval, int fd, uint32_t request, void* argp)
{
  if (fd == 0x0BEEF001)
  {
    if (request == 0x40048806)
    {
      *static_cast<uint32_t*>(argp) = 1;
      *retval = 0;
      return true;
    }
    else if (request == 0x40048807)
    {
      *static_cast<uint32_t*>(argp) = 0;
      *retval = 0;
      return true;
    }
    else if (request == 0x40088808)
    {
      *static_cast<uint64_t*>(argp) = 0;
      *retval = 0;
      return true;
    }
  }

  assert_always();
  *retval = -1;
  return false;
}

bool SYSCALLS::sysarch(Loader* loader, uint64_t* retval, int number, void* args)
{
  if (number == 129)
  {
    auto fsbase = *static_cast<void**>(args);
    printf("FSBASE=%p, %p\n", args, fsbase);
    loader->set_fsbase(fsbase);
    return true;
  }
  assert_always();
  *retval = -1;
  return false;
}

bool SYSCALLS::sysctl(
  Loader* loader, uint64_t* retval, int* name, uint32_t namelen, void* oldp, size_t* oldlenp, const void* newp, size_t newlen)
{
  if (namelen == 2 && name[0] == 0 && name[1] == 3)
  {
    auto name = std::string(static_cast<const char*>(newp), newlen);

    if (name == "kern.smp.cpus")
    {
      static_cast<uint32_t*>(oldp)[0] = 0x0BADF00D;
      static_cast<uint32_t*>(oldp)[1] = 1;
      *oldlenp = 8;
      return true;
    }
    else if (name == "kern.proc.ptc")
    {
      static_cast<uint32_t*>(oldp)[0] = 0x0BADF00D;
      static_cast<uint32_t*>(oldp)[1] = 2;
      *oldlenp = 8;
      return true;
    }
    else if (name == "machdep.tsc_freq")
    {
      static_cast<uint32_t*>(oldp)[0] = 0x0BADF00D;
      static_cast<uint32_t*>(oldp)[1] = 3;
      *oldlenp = 8;
      return true;
    }

    assert_always();
    return false;
  }
  else if (namelen == 2 && name[0] == 1 && name[1] == 33)
  {
    assert_true(*oldlenp == 8);
    *static_cast<void**>(oldp) = loader->user_stack_end_;
    return true;
  }
  else if (namelen == 2 && name[0] == 0x0BADF00D && name[1] == 1)
  {
    assert_true(*oldlenp == 4);
    *reinterpret_cast<uint32_t*>(oldp) = 1;
    return true;
  }
  else if (namelen == 2 && name[0] == 0x0BADF00D && name[1] == 2)
  {
    assert_true(*oldlenp == 8);
    *reinterpret_cast<uint64_t*>(oldp) = 1357;
    return true;
  }
  else if (namelen == 2 && name[0] == 0x0BADF00D && name[1] == 3)
  {
    assert_true(*oldlenp == 8);
    *reinterpret_cast<uint64_t*>(oldp) = 16000000000;
    return true;
  }
  else if (namelen == 2 && name[0] == 6 && name[1] == 7)
  {
    assert_true(*oldlenp == 4);
    *reinterpret_cast<uint32_t*>(oldp) = 4096;
    return true;
  }
  else if (namelen == 4 && name[0] == 1 && name[1] == 14 && name[2] == 35)
  {
    assert_true(*oldlenp == 72);
    std::memset(oldp, 0, 72);
    return true;
  }
  else if (namelen == 3 && name[0] == 1 && name[1] == 14 && name[2] == 41)
  {
    assert_true(*oldlenp == 4);
    *static_cast<uint32_t*>(oldp) = 0;
    return true;
  }
  else if (namelen == 4 && name[0] == 1 && name[1] == 14 && name[2] == 44)
  {
    assert_true(*oldlenp == 16);
    std::memset(oldp, 0, 16);
    return true;
  }

  assert_always();
  return false;
}

bool SYSCALLS::sigprocmask(Loader* loader, uint64_t* retval)
{
  return true;
}

bool SYSCALLS::sigaction(Loader* loader, uint64_t* retval)
{
  return true;
}

bool SYSCALLS::thr_self(Loader* loader, uint64_t* retval, void** arg1)
{
  *arg1 = (void*)357;
  *retval = 135;
  return true;
}

bool SYSCALLS::_umtx_op(Loader* loader, uint64_t* retval, void* obj, int op, uint32_t val, void* uaddr1, void* uaddr2)
{
  return true;
}

bool SYSCALLS::thr_set_name(Loader* loader, uint64_t* retval, long id, const char* name)
{
  printf("thr_set_name: %d=%s\n", id, name);
  return true;
}

bool SYSCALLS::rtprio_thread(Loader* loader, uint64_t* retval, int function, uint64_t lwpid, void* rtp)
{
  return true;
}

bool SYSCALLS::mmap(Loader* loader, uint64_t* retval, void* addr, size_t len, int prot, int	flags, int fd, off_t offset)
{
  auto access = xe::memory::PageAccess::kReadWrite;
  auto allocation_type = xe::memory::AllocationType::kReserveCommit;
  auto allocation = xe::memory::AllocFixed(0 /*addr*/, len, allocation_type, access);
  printf("mmap: addr=%p, len=%I64x, prot=%x, flags=%x, fd=%d, offset=%x, RETVAL=%p\n", addr, len, prot, flags, fd, offset, allocation);
  *reinterpret_cast<void**>(retval) = allocation ? allocation : (void*)-1;
  return allocation != nullptr;
}

struct nonsys_int
{
  union
  {
    uint64_t encoded_id;
    struct
    {
      uint8_t data[4];
      uint8_t table;
      uint8_t index;
      uint16_t checksum;
    }
    encoded_id_parts;
  };
  uint32_t unknown;
  uint32_t value;
};

bool SYSCALLS::regmgr_call(Loader* loader, uint64_t* retval, uint32_t op, uint32_t id, void* result, void* value, uint64_t type)
{
  if (op == 25) // non-system get int
  {
    auto int_value = static_cast<nonsys_int*>(value);

    if (int_value->encoded_id == 0x0CAE671ADF3AEB34ull ||
        int_value->encoded_id == 0x338660835BDE7CB1ull)
    {
      int_value->value = 0;
      *retval = true;
      return true;
    }

    *retval = 0x800D0203;
    return false;
  }

  *retval = -1;
  return false;
}

bool SYSCALLS::namedobj_create(Loader* loader, uint64_t* retval, const char* name, void* arg2, uint32_t arg3)
{
  printf("namedobj_create: %s %p %x\n", name, arg2, arg3);
  *retval = ++loader->next_namedobj_id_;
  return true;
}

bool SYSCALLS::get_authinfo(Loader* loader, uint64_t* retval, void* arg1, void* arg2)
{
  std::memset(arg2, 0, 136);
  return true;
}

bool SYSCALLS::mname(Loader* loader, uint64_t* retval, uint8_t* arg1, size_t arg2, const char* name, void* arg4)
{
  printf("mname: %p-%p=%s\n", arg1, &arg1[arg2] - 1, name);
  return true;
}

bool SYSCALLS::dynlib_dlsym(Loader* loader, uint64_t* retval, uint32_t id, const char* cname, void** sym)
{
  Linkable* module;
  if (!loader->FindModule(id, module))
  {
    *retval = -1;
    return false;
  }

  auto module_name = xe::to_string(module->name());
  auto index = module_name.rfind('.');
  if (index != std::string::npos)
  {
    module_name = module_name.substr(0, index);
  }

  auto name = std::string(cname);
  auto symbol_name = name + "#" + module_name + "#" + module_name;
  uint64_t symbol_value;
  if (module->ResolveSymbol(elf_hash(symbol_name.c_str()), symbol_name, symbol_value))
  {
    *sym = reinterpret_cast<void*>(symbol_value);
    return true;
  }

  std::string symbol_part;
  if (name == "sceSysmodulePreloadModuleForLibkernel")
  {
    symbol_part = "DOO+zuW1lrE";
  }
  else
  {
    *retval = -1;
    return false;
  }

  symbol_name = symbol_part + "#" + module_name + "#" + module_name;
  if (module->ResolveSymbol(elf_hash(symbol_name.c_str()), symbol_name, symbol_value))
  {
    *sym = reinterpret_cast<void*>(symbol_value);
    return true;
  }

  return false;
}

bool SYSCALLS::dynlib_get_list(Loader* loader, uint64_t* retval, void* arg1, void* arg2, size_t** arg3)
{
  *arg3 = nullptr;
  return true;
}

bool SYSCALLS::dynlib_load_prx(Loader* loader, uint64_t* retval, const char* cpath, void* arg2, uint32_t* arg3, void* arg4)
{
  printf("LOAD PRX: %s, %p, %p, %p\n", cpath, arg2, arg3, arg4);

  auto path = xe::to_wstring(cpath);

  auto index = path.rfind('/');
  if (index != std::wstring::npos)
  {
    path = path.substr(index + 1);
  }

  Linkable* module;
  if (loader->LoadModule(path, module))
  {
    module->Relocate();
    *arg3 = module->id();
    *retval = 0;
    return true;
  }

  if (path.length() >= 5 && path.substr(path.length() - 5) == L".sprx")
  {
    if (loader->LoadModule(path.substr(0, path.length() - 5) + L".prx", module))
    {
      module->Relocate();
      *arg3 = module->id();
      *retval = 0;
      return true;
    }
  }

  printf("LOAD PRX FAILED!\n");
  *retval = -1;
  return false;
}

bool SYSCALLS::dynlib_do_copy_relocations(Loader* loader, uint64_t* retval)
{
  return true;
}

bool SYSCALLS::dynlib_get_proc_param(Loader* loader, uint64_t* retval, void** data_address, size_t* data_size)
{
  auto eboot = loader->objects_.begin()->get();
  auto base_address = eboot->base_address();
  *data_address = base_address ? &base_address[eboot->sce_proc_param_address()] : nullptr;
  *data_size = eboot->sce_proc_param_size();
  return true;
}

bool SYSCALLS::dynlib_process_needed_and_relocate(Loader* loader, uint64_t* retval)
{
  bool success = loader->LoadNeededObjects() && loader->RelocateObjects();
  *retval = success ? 0 : -1;
  return success;
}

bool SYSCALLS::mdbg_service(Loader* loader, uint64_t* retval, void* arg1, void* arg2, void* arg3)
{
  return true;
}

bool SYSCALLS::randomized_path(Loader* loader, uint64_t* retval, const char* set_path, char* path, size_t* path_length)
{
  if (set_path != nullptr)
  {
    *retval = -1;
    return false;
  }

  *path_length = snprintf(path, *path_length, "uplift");
  return true;
}

bool SYSCALLS::workaround8849(Loader* loader, uint64_t* retval)
{
  return true;
}

struct dynlib_info_ex
{
  uint64_t struct_size;
  char name[256];
  uint32_t unknown_108;
  uint16_t unknown_10C;
  uint16_t unknown_10E;
  void* tls_address;
  uint32_t tls_file_size;
  uint32_t tls_memory_size;
  uint32_t unknown_120;
  uint32_t tls_align;
  void* init_address;
  void* fini_address;
  uint64_t unknown_138;
  uint64_t unknown_140;
  void* u6474E550_address;
  void* frame_info_1;
  uint32_t u6474E550_memory_size;
  uint32_t frame_info_2;
  uint64_t unknown_160;
  uint32_t unknown_168;
  uint32_t unknown_16C;
  uint64_t unknown_170;
  uint32_t unknown_178;
  uint32_t unknown_17C;
  uint8_t unknown_180[32];
  uint32_t unknown_1A0;
  uint32_t unknown_1A4;
};

bool SYSCALLS::dynlib_get_info_ex(Loader* loader, uint64_t* retval, uint32_t id, void* arg2, void* vinfo)
{
  if (static_cast<dynlib_info_ex*>(vinfo)->struct_size != sizeof(dynlib_info_ex))
  {
    *retval = -1;
    return false;
  }

  dynlib_info_ex ex;
  std::memset(&ex, 0, sizeof(dynlib_info_ex));

  Linkable* module;
  if (!loader->FindModule(id, module))
  {
    *retval = -1;
    return false;
  }

  auto name = xe::to_string(module->name());
  auto index = name.rfind('.');
  if (index != std::string::npos)
  {
    name = name.substr(0, index);
  }

  auto base_address = module->base_address();
  auto program_info = module->program_info();
  auto dynamic_info = module->dynamic_info();

  std::strncpy(ex.name, name.c_str(), sizeof(ex.name));
  ex.struct_size = sizeof(dynlib_info_ex);
  ex.tls_address = !program_info.tls_address ? nullptr : &base_address[program_info.tls_address];
  ex.tls_file_size = static_cast<uint32_t>(program_info.tls_file_size);
  ex.tls_memory_size = static_cast<uint32_t>(program_info.tls_memory_size);
  ex.tls_align = static_cast<uint32_t>(program_info.tls_align);
  ex.init_address = !dynamic_info.init_offset ? nullptr : &base_address[dynamic_info.init_offset];
  ex.fini_address = !dynamic_info.fini_offset ? nullptr : &base_address[dynamic_info.fini_offset];
  ex.u6474E550_address = !program_info.u6474E550_address ? nullptr : &base_address[program_info.u6474E550_address];
  ex.u6474E550_memory_size = static_cast<uint32_t>(program_info.u6474E550_memory_size);
  ex.unknown_1A0 = 1;
  std::memcpy(vinfo, &ex, sizeof(dynlib_info_ex));
  return true;
}

// arg1 removed after 1.76 sometime?
bool SYSCALLS::eport_create(Loader* loader, uint64_t* retval, /*const char* arg1,*/ uint32_t arg2)
{
  printf("eport_create: %x\n", arg2);
  *retval = 78;
  return false;
}

bool SYSCALLS::get_proc_type_info(Loader* loader, uint64_t* retval, void* vtype_info)
{
  struct
  {
    size_t struct_size;
    uint32_t budget;
    uint32_t flags;
  }
  type_info = { sizeof(type_info), 0, 0 };
  std::memcpy(vtype_info, &type_info, sizeof(type_info));
  *retval = 0;
  return true;
}

bool SYSCALLS::ipmimgr_call(Loader* loader, uint64_t* retval)
{
  assert_always();
  *retval = -1;
  return false;
}

void uplift::get_syscall_table(SyscallEntry table[1024])
{
#define SYSCALL(x,y,...) { table[x].handler = SYSCALLS::y; table[x].name = #y; }
#include "syscall_table.inl"
#undef SYSCALL
}
