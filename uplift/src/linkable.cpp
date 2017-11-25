#include "stdafx.h"

#include <algorithm>

#include <xenia/base/assert.h>
#include <xenia/base/debugging.h>
#include <xenia/base/mapped_memory.h>
#include <xenia/base/memory.h>
#include <xenia/base/string.h>

#define NOMINMAX
#include <windows.h>

#include <llvm/BinaryFormat/ELF.h>

#include "../../capstone/include/capstone.h"
#include "../../capstone/include/x86.h"

#include "../../xbyak/xbyak/xbyak.h"

#include "loader.hpp"
#include "linkable.hpp"
#include "program_info.hpp"
#include "dynamic_info.hpp"
#include "helpers.hpp"
#include "match.hpp"
#include "code_generators.hpp"

using namespace uplift;
namespace elf = llvm::ELF;

bool is_loadable(elf::Elf64_Word type)
{
  return type == elf::PT_LOAD || type == 0x61000010ull;
}

std::unique_ptr<Linkable> Linkable::Load(Loader* loader, const std::wstring& path)
{
  if (loader == nullptr)
  {
    return nullptr;
  }

  auto map = xe::MappedMemory::Open(path, xe::MappedMemory::Mode::kRead);
  if (map == nullptr)
  {
    return nullptr;
  }

  auto data = map->data();

  auto ehdr = reinterpret_cast<elf::Elf64_Ehdr*>(data);
  if (!ehdr->checkMagic())
  {
    return nullptr;
  }

  if (ehdr->getFileClass() != elf::ELFCLASS64)
  {
    return nullptr;
  }

  if (ehdr->getDataEncoding() != elf::ELFDATA2LSB)
  {
    return nullptr;
  }

  if (ehdr->e_type != elf::ET_EXEC && ehdr->e_type != 0xFE00u && ehdr->e_type != 0xFE10u && ehdr->e_type != 0xFE18u)
  {
    return nullptr;
  }

  if (ehdr->e_machine != elf::EM_X86_64)
  {
    return nullptr;
  }

  if (ehdr->e_version != llvm::ELF::EV_CURRENT)
  {
    return nullptr;
  }

  ProgramInfo info;
  if (!get_program_info(reinterpret_cast<elf::Elf64_Phdr*>(&ehdr[1]), ehdr->e_phnum, info))
  {
    return nullptr;
  }

  std::vector<elf::Elf64_Phdr> phdrs;
  for (elf::Elf64_Half i = 0; i < ehdr->e_phnum; ++i)
  {
    auto phdr = &reinterpret_cast<elf::Elf64_Phdr*>(&ehdr[1])[i];
    phdrs.push_back(*phdr);
  }

  if (!info.has_dynamic && ehdr->e_type == 0xFE10u)
  {
    return nullptr;
  }

  bool had_error = false;
  uint8_t* dynamic_buffer = nullptr;
  uint8_t* sce_dynlibdata_buffer = nullptr;

  if (info.has_dynamic)
  {
    if (!info.dynamic_file_size || !info.sce_dynlibdata_file_size)
    {
      goto error;
    }

    dynamic_buffer = static_cast<uint8_t*>(xe::memory::AllocFixed(
      nullptr,
      info.dynamic_file_size,
      xe::memory::AllocationType::kReserveCommit,
      xe::memory::PageAccess::kReadWrite));
    if (dynamic_buffer == nullptr)
    {
      goto error;
    }

    std::memcpy(dynamic_buffer, &data[info.dynamic_file_offset], info.dynamic_file_size);

    sce_dynlibdata_buffer = static_cast<uint8_t*>(xe::memory::AllocFixed(
      nullptr,
      info.sce_dynlibdata_file_size,
      xe::memory::AllocationType::kReserveCommit,
      xe::memory::PageAccess::kReadWrite));
    if (sce_dynlibdata_buffer == nullptr)
    {
      goto error;
    }

    std::memcpy(sce_dynlibdata_buffer, &data[info.sce_dynlibdata_file_offset], info.sce_dynlibdata_file_size);
  }

  auto load_size = info.load_end - info.load_start;

  union address
  {
    uint8_t* ptr;
    uint64_t val;
  };

  const size_t one_mb = 1ull * 1024ull * 1024ull;
  const size_t eight_mb = 8ull * one_mb;
  const size_t four_gb = 4ull * 1024ull * one_mb;
  const size_t eight_gb = 8ull * 1024ull * one_mb;

  /* 8GiB is reserved so that the loaded module has a guaranteed
   * 4GB address space all to itself, and then some.
   *
   * xxxxxxxx00000000 - xxxxxxxxFFFFFFFF
   *
   * Once the range is mapped, a safe area before or after the
   * size of the loaded module is chosen to store any extra
   * code or data that is easily RIP addressable.
   */

  address reserved_address;
  reserved_address.ptr = static_cast<uint8_t*>(xe::memory::AllocFixed(
    nullptr,
    eight_gb,
    xe::memory::AllocationType::kReserve,
    xe::memory::PageAccess::kNoAccess));
  if (reserved_address.ptr == nullptr)
  {
    goto error;
  }

  const size_t page_size = 0x4000;

  struct rip_zone_definition
  {
    RIPPointers rip_pointers;
    uint8_t padding1[align_size_const(sizeof(RIPPointers), page_size) - sizeof(RIPPointers)];
    uint8_t safe1[page_size];
    uint8_t free_zone[eight_mb];
    //uint8_t padding2[align_size_const(eight_mb, page_size) - eight_mb];
    uint8_t safe2[page_size];
  };

  const size_t desired_rip_zone_size = sizeof(rip_zone_definition);

  address base_address;
  base_address.val = align_size(reserved_address.val, four_gb);

  auto reserved_before_size = static_cast<size_t>(base_address.ptr - reserved_address.ptr);
  auto reserved_after_size = static_cast<size_t>(&reserved_address.ptr[eight_gb] - &base_address.ptr[load_size]);

  address rip_zone_start, rip_zone_end;

  if (reserved_before_size >= desired_rip_zone_size)
  {
    rip_zone_start.val = reserved_before_size + load_size < INT32_MAX
      ? align_size(reserved_address.val + load_size, page_size)
      : align_size(base_address.val + load_size + INT32_MIN, page_size);
    rip_zone_end.ptr = &rip_zone_start.ptr[desired_rip_zone_size];
    assert_true(rip_zone_start.ptr >= reserved_address.ptr && rip_zone_end.ptr <= base_address.ptr);
  }
  else if (reserved_after_size >= desired_rip_zone_size)
  {
    rip_zone_start.val = align_size(base_address.val + load_size, page_size);
    rip_zone_end.ptr = &rip_zone_start.ptr[desired_rip_zone_size];
    assert_true(rip_zone_start.ptr >= &base_address.ptr[load_size] && rip_zone_end.ptr <= &reserved_address.ptr[eight_gb]);
  }
  else
  {
    assert_always();
  }

  auto rip_zone_data = reinterpret_cast<rip_zone_definition*>(rip_zone_start.ptr);

  auto rip_pointers = &rip_zone_data->rip_pointers;
  if (xe::memory::AllocFixed(
    rip_pointers,
    sizeof(RIPPointers),
    xe::memory::AllocationType::kCommit,
    xe::memory::PageAccess::kReadWrite) != rip_pointers)
  {
    goto error;
  }

  rip_pointers->loader = loader;
  rip_pointers->syscall_handler = loader->syscall_handler();

  auto free_zone = &rip_zone_data->free_zone[0];
  if (xe::memory::AllocFixed(
    free_zone,
    sizeof(rip_zone_definition::free_zone),
    xe::memory::AllocationType::kCommit,
    xe::memory::PageAccess::kExecuteReadWrite) != free_zone)
  {
    goto error;
  }

  for (elf::Elf64_Half i = 0; i < ehdr->e_phnum; ++i)
  {
    auto phdr = &reinterpret_cast<elf::Elf64_Phdr*>(&ehdr[1])[i];
    if (!is_loadable(phdr->p_type) || phdr->p_memsz == 0)
    {
      continue;
    }

    auto program_address = &base_address.ptr[phdr->p_vaddr];
    auto program_allocated_address = xe::memory::AllocFixed(
      program_address,
      phdr->p_memsz,
      xe::memory::AllocationType::kCommit,
      xe::memory::PageAccess::kReadWrite);
    if (program_allocated_address == nullptr || program_allocated_address != program_address)
    {
      goto error;
    }

    std::memcpy(program_address, &data[phdr->p_offset], phdr->p_filesz);

    if (phdr->p_memsz > phdr->p_filesz)
    {
      std::memset(&program_address[phdr->p_filesz], 0, phdr->p_memsz - phdr->p_filesz);
    }
  }

  // we're good
  {
    auto linkable = std::make_unique<Linkable>(loader, path);
    linkable->type_ = ehdr->e_type;
    linkable->dynamic_buffer_ = dynamic_buffer;
    linkable->dynamic_size_ = info.dynamic_file_size;
    linkable->sce_dynlibdata_buffer_ = sce_dynlibdata_buffer;
    linkable->sce_dynlibdata_size_ = info.sce_dynlibdata_file_size;
    linkable->reserved_address_ = reserved_address.ptr;
    linkable->reserved_prefix_size_ = reserved_before_size;
    linkable->reserved_suffix_size_ = reserved_after_size;
    linkable->base_address_ = base_address.ptr;
    linkable->rip_pointers_ = rip_pointers;
    linkable->rip_zone_ =
    {
      &free_zone[0],
      &free_zone[0],
      &free_zone[sizeof(rip_zone_definition::free_zone)],
    };
    linkable->sce_proc_param_address_ = info.sce_proc_param_address;
    linkable->sce_proc_param_size_ = info.sce_proc_param_file_size;
    linkable->entrypoint_ = ehdr->e_entry;
    for (elf::Elf64_Half i = 0; i < ehdr->e_phnum; ++i)
    {
      auto phdr = &reinterpret_cast<elf::Elf64_Phdr*>(&ehdr[1])[i];
      if (!is_loadable(phdr->p_type) || phdr->p_memsz == 0)
      {
        continue;
      }
      linkable->load_headers_.push_back(*phdr);
    }
    linkable->program_info_ = info;
    linkable->ProcessDynamic();
    linkable->AnalyzeAndPatchCode();
    linkable->Protect();

    xe::debugging::DebugPrint("MODULE = %S @ %p\n", linkable->name().c_str(), base_address.ptr);

    return std::move(linkable);
  }

error:
  if (free_zone)
  {
    xe::memory::DeallocFixed(free_zone, 0, xe::memory::DeallocationType::kRelease);
  }
  if (rip_pointers)
  {
    xe::memory::DeallocFixed(rip_pointers, 0, xe::memory::DeallocationType::kRelease);
  }
  if (reserved_address.ptr)
  {
    xe::memory::DeallocFixed(reserved_address.ptr, 0, xe::memory::DeallocationType::kRelease);
  }
  if (sce_dynlibdata_buffer)
  {
    xe::memory::DeallocFixed(sce_dynlibdata_buffer, 0, xe::memory::DeallocationType::kRelease);
  }
  if (dynamic_buffer)
  {
    xe::memory::DeallocFixed(dynamic_buffer, 0, xe::memory::DeallocationType::kRelease);
  }
  return nullptr;
}

Linkable::Linkable(Loader* loader, const std::wstring& path)
  : loader_(loader)
  , path_(path)
  , name_(xe::find_name_from_path(path))
  , type_(0)
  , dynamic_buffer_(nullptr)
  , dynamic_size_(0)
  , sce_dynlibdata_buffer_(nullptr)
  , sce_dynlibdata_size_(0)
  , sce_comment_buffer_(nullptr)
  , sce_comment_size_(0)
  , reserved_address_(nullptr)
  , reserved_prefix_size_(0)
  , reserved_suffix_size_(0)
  , base_address_(nullptr)
  , rip_pointers_(nullptr)
  , rip_zone_()
  , sce_proc_param_address_(0)
  , sce_proc_param_size_(0)
  , entrypoint_(0)
  , program_info_()
  , dynamic_info_()
{
}

Linkable::~Linkable()
{
  if (rip_pointers_)
  {
    xe::memory::DeallocFixed(rip_pointers_, 0, xe::memory::DeallocationType::kRelease);
    rip_pointers_ = nullptr;
  }
  if (reserved_address_)
  {
    xe::memory::DeallocFixed(reserved_address_, 0, xe::memory::DeallocationType::kRelease);
    reserved_address_ = nullptr;
  }
  if (sce_dynlibdata_buffer_)
  {
    xe::memory::DeallocFixed(sce_dynlibdata_buffer_, 0, xe::memory::DeallocationType::kRelease);
    sce_dynlibdata_buffer_ = nullptr;
  }
  if (dynamic_buffer_)
  {
    xe::memory::DeallocFixed(dynamic_buffer_, 0, xe::memory::DeallocationType::kRelease);
    dynamic_buffer_ = nullptr;
  }
}

void Linkable::ProcessDynamic()
{
  if (!get_dynamic_info(
    reinterpret_cast<elf::Elf64_Dyn*>(dynamic_buffer_),
    dynamic_size_ / sizeof(elf::Elf64_Dyn),
    sce_dynlibdata_buffer_,
    sce_dynlibdata_size_,
    dynamic_info_))
  {
    assert_always();
  }
}

bool patch_fsbase_access(uint8_t* target, cs_insn* insn, RIPPointers* rip_pointers, RIPZone& rip_zone)
{
  if (insn->id == X86_INS_MOV)
  {
    if (insn->detail->x86.op_count != 2)
    {
      assert_always();
      return false;
    }

    auto operands = insn->detail->x86.operands;

    if (operands[0].type != X86_OP_REG)
    {
      assert_always();
      return false;
    }

    if (operands[1].type != X86_OP_MEM ||
        operands[1].mem.segment != X86_REG_FS ||
        operands[1].mem.base != X86_REG_INVALID ||
        operands[1].mem.index != X86_REG_INVALID)
    {
      assert_always();
      return false;
    }

    using Generator = code_generators::FSBaseMovGenerator;

    Generator generator(operands[0].reg, operands[0].size, operands[1].mem.disp);

    auto trampoline_code = generator.getCode();
    auto trampoline_size = generator.getSize();
    auto aligned_size = align_size(trampoline_size, 32);

    uint8_t* rip_code;
    if (!rip_zone.take(aligned_size, rip_code))
    {
      assert_always();
      return false;
    }

    std::memcpy(rip_code, trampoline_code, trampoline_size);

    auto tail = reinterpret_cast<Generator::Tail*>(&rip_code[trampoline_size - sizeof(Generator::Tail)]);
    tail->target = &target[insn->size];
    tail->rip_pointers = rip_pointers;

    if (trampoline_size < aligned_size)
    {
      memset(&rip_code[trampoline_size], 0xCC, aligned_size - trampoline_size);
    }

    assert_true(insn->size >= 5);

    auto disp = static_cast<uint32_t>(rip_code - &target[5]);
    target[0] = 0xE9;
    *reinterpret_cast<uint32_t*>(&target[1]) = disp;

    if (5 < insn->size)
    {
      std::memset(&target[5], 0xCC, insn->size - 5);
    }

    return true;
  }
  else
  {
    assert_always();
    return false;
  }
}

bool hook_syscall(uint64_t id, uint8_t* target, size_t target_size, RIPPointers* rip_pointers, RIPZone& rip_zone)
{
  if (id == UINT64_MAX)
  {
    using Generator = code_generators::SyscallTrampolineGenerator;
    Generator generator;

    auto trampoline_code = generator.getCode();
    auto trampoline_size = generator.getSize();
    auto aligned_size = align_size(trampoline_size, 32);

    uint8_t* rip_code;
    if (!rip_zone.take(aligned_size, rip_code))
    {
      assert_always();
      return false;
    }

    std::memcpy(rip_code, trampoline_code, trampoline_size);

    auto tail = reinterpret_cast<Generator::Tail*>(&rip_code[trampoline_size - sizeof(Generator::Tail)]);
    tail->target = &target[target_size];
    tail->rip_pointers = rip_pointers;

    if (trampoline_size < aligned_size)
    {
      memset(&rip_code[trampoline_size], 0xCC, aligned_size - trampoline_size);
    }

    auto disp = static_cast<uint32_t>(rip_code - &target[5]);
    target[0] = 0xE9;
    *reinterpret_cast<uint32_t*>(&target[1]) = disp;
    return true;
  }
  else
  {
    using Generator = code_generators::NakedSyscallTrampolineGenerator;
    Generator generator(id);

    auto trampoline_code = generator.getCode();
    auto trampoline_size = generator.getSize();
    auto aligned_size = align_size(trampoline_size, 32);

    uint8_t* rip_code;
    if (!rip_zone.take(aligned_size, rip_code))
    {
      assert_always();
      return false;
    }

    std::memcpy(rip_code, trampoline_code, trampoline_size);

    auto tail = reinterpret_cast<Generator::Tail*>(&rip_code[trampoline_size - sizeof(Generator::Tail)]);
    tail->target = &target[target_size];
    tail->rip_pointers = rip_pointers;

    if (trampoline_size < aligned_size)
    {
      memset(&rip_code[trampoline_size], 0xCC, aligned_size - trampoline_size);
    }

    auto disp = static_cast<uint32_t>(rip_code - &target[5]);
    target[0] = 0xE9;
    *reinterpret_cast<uint32_t*>(&target[1]) = disp;
    target[5] = 0xCC;
    target[6] = 0xCC;
    target[7] = 0xCC;
    target[8] = 0xCC;
    return true;
  }
  assert_always();
  return false;
}

bool hook_bmi1_instruction(uint8_t* target, cs_insn* insn, RIPPointers* rip_pointers, RIPZone& rip_zone)
{
  //assert_always();
  return true;
}

bool is_bmi1(x86_insn op)
{
  return op == X86_INS_ANDN ||
    op == X86_INS_BEXTR ||
    op == X86_INS_BLSI ||
    op == X86_INS_BLSMSK ||
    op == X86_INS_BLSR ||
    op == X86_INS_TZCNT;
}

void Linkable::AnalyzeAndPatchCode()
{
  if (name_ == L"libkernel.prx")
  {
    *reinterpret_cast<uint32_t*>(&base_address_[0x6036C]) = 0xFFFFFFFF;
  }

  elf::Elf64_Phdr phdr;
  bool found_code = false;
  for (auto it = load_headers_.begin(); it != load_headers_.end(); ++it)
  {
    phdr = *it;
    if (phdr.p_flags & elf::PF_X)
    {
      found_code = true;
      break;
    }
  }

  if (!found_code)
  {
    return;
  }

  auto program_buffer = &base_address_[phdr.p_vaddr];
  uint8_t* text_buffer;
  size_t text_size;
  if (!get_text_region(program_buffer, phdr.p_filesz, text_buffer, text_size))
  {
    assert_always();
    return;
  }

  csh handle;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
  {
    assert_always();
    return;
  }
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

  auto insn = cs_malloc(handle);
  const uint8_t* code = text_buffer;
  size_t code_size = text_size;
  uint64_t address = phdr.p_vaddr + (text_buffer - program_buffer);
  while (cs_disasm_iter(handle, &code, &code_size, &address, insn))
  {
    if (insn->id == X86_INS_SYSCALL)
    {
      assert_true(insn->size == 2);
      auto target = &program_buffer[insn->address];

      uint16_t syscall_pattern[] = { 0x49, 0x89, 0xCA, 0x0F, 0x05 };
      uint16_t naked_syscall_pattern[] = { 0x48, 0xC7, 0xC0, MATCH_ANY, MATCH_ANY, MATCH_ANY, MATCH_ANY, 0x0F, 0x05 };

#define IS_SYSCALL_MATCH(x) \
  (match_buffer(&target[-(_countof(x) - 2)], _countof(x), x, _countof(x), &match) && &target[-(_countof(x) - 2)] == match)
      void* match;
#pragma warning(suppress: 4146)
      if (IS_SYSCALL_MATCH(syscall_pattern))
      {
        hook_syscall(UINT64_MAX, &target[-3], _countof(syscall_pattern), rip_pointers_, rip_zone_);
      }
#pragma warning(suppress: 4146)
      else if (IS_SYSCALL_MATCH(naked_syscall_pattern))
      {
        auto syscall_id = *reinterpret_cast<uint32_t*>(&target[-4]);
        hook_syscall(syscall_id, &target[-7], _countof(naked_syscall_pattern), rip_pointers_, rip_zone_);
      }
      else
      {
        assert_always();
      }
#undef IS_SYSCALL_MATCH
    }
    else if (insn->id == X86_INS_INT)
    {
      assert_true(insn->size == 2);
      auto target = &program_buffer[insn->address];
      target[0] = 0x0F;
      target[1] = 0x0B;
      interrupts_[target] = (uint8_t)insn->detail->x86.operands[0].imm;
    }
    else if (insn->id == X86_INS_INT1)
    {
      assert_unhandled_case(X86_INS_INTO);
    }
    else if (insn->id == X86_INS_INTO)
    {
      assert_unhandled_case(X86_INS_INTO);
    }
    else if (!loader_->cpu_has(Xbyak::util::Cpu::tBMI1) && is_bmi1((x86_insn)insn->id))
    {
      assert_true(insn->size >= 5);
      auto target = &program_buffer[insn->address];
      if (!hook_bmi1_instruction(target, insn, rip_pointers_, rip_zone_))
      {
        assert_always();
      }
    }
    else
    {
      bool is_fs = false;
      for (uint8_t i = 0; i < insn->detail->x86.op_count; i++)
      {
        auto operand = insn->detail->x86.operands[i];
        if (operand.type == X86_OP_MEM &&
            operand.mem.segment == X86_REG_FS)
        {
          is_fs = true;
          break;
        }
      }

      if (is_fs)
      {
        auto target = &program_buffer[insn->address];
        patch_fsbase_access(target, insn, rip_pointers_, rip_zone_);
      }
    }
  }
  cs_free(insn, 1);
  cs_close(&handle);
}

struct StringTable
{
  const char* buffer;
  size_t length;

  const char* get(size_t offset)
  {
    return offset < length ? &buffer[offset] : nullptr;
  }
};

void Linkable::set_fsbase(void* fsbase)
{
  if (!rip_pointers_)
  {
    return;
  }

  rip_pointers_->fsbase = fsbase;
}

bool Linkable::ResolveSymbol(uint32_t symbol_name_hash, const std::string& symbol_name, uint64_t& value)
{
  auto hash_table = reinterpret_cast<elf::Elf64_Word*>(&sce_dynlibdata_buffer_[dynamic_info_.hash_table_offset]);
  auto bucket_count = hash_table[0];
  auto chain_count = hash_table[1];
  auto buckets = &hash_table[2];
  auto chains = &buckets[bucket_count];

  auto symbols = reinterpret_cast<elf::Elf64_Sym*>(&sce_dynlibdata_buffer_[dynamic_info_.symbol_table_offset]);
  auto symbol_count = dynamic_info_.symbol_table_size / sizeof(elf::Elf64_Sym);
  auto symbol_end = &symbols[symbol_count];

  StringTable string_table =
  {
    reinterpret_cast<const char*>(&sce_dynlibdata_buffer_[dynamic_info_.string_table_offset]),
    dynamic_info_.string_table_size,
  };

  for (elf::Elf64_Word index = buckets[symbol_name_hash % bucket_count]; index != elf::STN_UNDEF; index = chains[index])
  {
    if (index >= chain_count)
    {
      return false;
    }
    assert_true(index < symbol_count);
    auto candidate_symbol = symbols[index];
    auto candidate_local_name = string_table.get(candidate_symbol.st_name);
    std::string candidate_symbol_name;
    uint16_t candidate_module_id, candidate_library_id;
    if (parse_symbol_name(candidate_local_name, candidate_symbol_name, candidate_library_id, candidate_module_id))
    {
      ModuleInfo candidate_module;
      LibraryInfo candidate_library;
      if (dynamic_info_.find_module(candidate_module_id, candidate_module) &&
          dynamic_info_.find_library(candidate_library_id, candidate_library))
      {
        if (!candidate_library.is_export)
        {
          continue;
        }

        auto candidate_name = candidate_symbol_name + "#" + candidate_library.name + "#" + candidate_module.name;
        if (candidate_name == symbol_name)
        {
          value = reinterpret_cast<uint64_t>(&base_address_[candidate_symbol.st_value]);
          return true;
        }
      }
    }
  }
  return false;
}

bool Linkable::ResolveExternalSymbol(const std::string& local_name, uint64_t& value)
{
  std::string symbol_name;
  uint16_t module_id, library_id;
  if (!parse_symbol_name(local_name, symbol_name, library_id, module_id))
  {
    assert_always();
    return false;
  }

  ModuleInfo module;
  LibraryInfo library;
  if (!dynamic_info_.find_module(module_id, module) ||
      !dynamic_info_.find_library(library_id, library))
  {
    assert_always();
    return false;
  }

  auto name = symbol_name + "#" + library.name + "#" + module.name;
  auto name_hash = elf_hash(name.c_str());
  if (!loader_->ResolveSymbol(nullptr, name_hash, name, value))
  {
    printf("FAILED TO RESOLVE: %s\n", name.c_str());

    name = "M0z6Dr6TNnM#libkernel#libkernel"; // sceKernelReportUnpatchedFunctionCall
    name_hash = elf_hash(name.c_str());
    if (!loader_->ResolveSymbol(nullptr, name_hash, name, value))
    {
      assert_always();
      return false;
    }
  }
  return true;
}

bool Linkable::Relocate()
{
  Unprotect();
  auto result = RelocateRela() && RelocatePltRela();
  Protect();
  return result;
}

bool Linkable::RelocateRela()
{
  StringTable string_table =
  {
    reinterpret_cast<const char*>(&sce_dynlibdata_buffer_[dynamic_info_.string_table_offset]),
    dynamic_info_.string_table_size,
  };
  auto symbols = reinterpret_cast<elf::Elf64_Sym*>(&sce_dynlibdata_buffer_[dynamic_info_.symbol_table_offset]);
  auto symbol_end = &symbols[dynamic_info_.symbol_table_size / sizeof(elf::Elf64_Sym)];
  auto rela = reinterpret_cast<elf::Elf64_Rela*>(&sce_dynlibdata_buffer_[dynamic_info_.rela_table_offset]);
  auto rela_end = &rela[dynamic_info_.rela_table_size / sizeof(elf::Elf64_Rela)];
  for (; rela < rela_end; ++rela)
  {
    auto type = rela->getType();
    uint64_t symval;
    switch (type)
    {
      case elf::R_X86_64_64:
      case elf::R_X86_64_PC32:
      case elf::R_X86_64_GLOB_DAT:
      case elf::R_X86_64_TPOFF64:
      case elf::R_X86_64_TPOFF32:
      case elf::R_X86_64_DTPMOD64:
      case elf::R_X86_64_DTPOFF64:
      case elf::R_X86_64_DTPOFF32:
      {
        auto symbol = symbols[rela->getSymbol()];
        if (symbol.getBinding() == elf::STB_LOCAL)
        {
          symval = reinterpret_cast<uint64_t>(base_address_) + symbol.st_value;
        }
        else if (symbol.getBinding() == elf::STB_GLOBAL || symbol.getBinding() == elf::STB_WEAK)
        {
          auto local_name = string_table.get(symbol.st_name);
          if (!this->ResolveExternalSymbol(local_name, symval))
          {
            assert_always();
            return false;
          }
        }
        else
        {
          assert_always();
          return false;
        }
        break;
      }

      case elf::R_X86_64_RELATIVE:
      {
        symval = 0;
        break;
      }

      default:
      {
        assert_always();
        return false;
      }
    }

    auto target = &base_address_[rela->r_offset];
    switch (type)
    {
      case elf::R_X86_64_NONE:
      {
        break;
      }

      case elf::R_X86_64_64:
      {
        *reinterpret_cast<uint64_t*>(target) = symval + rela->r_addend;
        break;
      }

      case elf::R_X86_64_PC32:
      {
        auto value = static_cast<uint32_t>(symval + rela->r_addend - reinterpret_cast<uint64_t>(target));
        *reinterpret_cast<uint32_t*>(target) = value;
        break;
      }

      case elf::R_X86_64_COPY:
      {
        assert_always();
        return false;
      }

      case elf::R_X86_64_GLOB_DAT:
      {
        *reinterpret_cast<uint64_t*>(target) = symval;
        break;
      }

      case elf::R_X86_64_TPOFF64:
      {
        assert_always();
        return false;
      }

      case elf::R_X86_64_TPOFF32:
      {
        assert_always();
        return false;
      }

      case elf::R_X86_64_DTPMOD64:
      {
        //assert_always();
        break;
      }

      case elf::R_X86_64_DTPOFF64:
      {
        *reinterpret_cast<uint64_t*>(target) += symval + rela->r_addend;
        break;
      }

      case elf::R_X86_64_DTPOFF32:
      {
        *reinterpret_cast<uint32_t*>(target) += static_cast<uint32_t>(symval + rela->r_addend);
        break;
      }

      case elf::R_X86_64_RELATIVE:
      {
        *reinterpret_cast<uint64_t*>(target) = reinterpret_cast<uint64_t>(base_address_) + rela->r_addend;
        break;
      }

      default:
      {
        assert_always();
        return false;
      }
    }
  }
  return true;
}

bool Linkable::RelocatePltRela()
{
  StringTable string_table =
  {
    reinterpret_cast<const char*>(&sce_dynlibdata_buffer_[dynamic_info_.string_table_offset]),
    dynamic_info_.string_table_size,
  };
  auto symbols = reinterpret_cast<elf::Elf64_Sym*>(&sce_dynlibdata_buffer_[dynamic_info_.symbol_table_offset]);
  auto symbol_end = &symbols[dynamic_info_.symbol_table_size / sizeof(elf::Elf64_Sym)];
  auto rela = reinterpret_cast<elf::Elf64_Rela*>(&sce_dynlibdata_buffer_[dynamic_info_.pltrela_table_offset]);
  auto rela_end = &rela[dynamic_info_.pltrela_table_size / sizeof(elf::Elf64_Rela)];
  for (; rela < rela_end; ++rela)
  {
    auto type = rela->getType();
    uint64_t symval;
    switch (type)
    {
      case elf::R_X86_64_JUMP_SLOT:
      {
        auto symbol = symbols[rela->getSymbol()];
        if (symbol.getBinding() == elf::STB_LOCAL)
        {
          symval = reinterpret_cast<uint64_t>(base_address_) + symbol.st_value;
        }
        else if (symbol.getBinding() == elf::STB_GLOBAL || symbol.getBinding() == elf::STB_WEAK)
        {
          auto local_name = string_table.get(symbol.st_name);
          if (!this->ResolveExternalSymbol(local_name, symval))
          {
            assert_always();
            return false;
          }
        }
        else
        {
          assert_always();
          return false;
        }
        break;
      }

      case elf::R_X86_64_RELATIVE:
      {
        symval = 0;
        break;
      }

      default:
      {
        assert_always();
        return false;
      }
    }

    auto target = &base_address_[rela->r_offset];
    switch (type)
    {
      case elf::R_X86_64_JUMP_SLOT:
      {
        *reinterpret_cast<uint64_t*>(target) = symval;
        break;
      }

      default:
      {
        assert_always();
        return false;
      }
    }
  }
  return true;
}

void Linkable::Protect()
{
  for (auto it = load_headers_.begin(); it != load_headers_.end(); ++it)
  {
    auto phdr = *it;
    auto program_address = &base_address_[phdr.p_vaddr];
    xe::memory::Protect(program_address, phdr.p_memsz, get_page_access(phdr.p_flags), nullptr);
  }
}

void Linkable::Unprotect()
{
  for (auto it = load_headers_.begin(); it != load_headers_.end(); ++it)
  {
    auto phdr = *it;
    auto program_address = &base_address_[phdr.p_vaddr];
    xe::memory::Protect(program_address, phdr.p_memsz, xe::memory::PageAccess::kReadWrite, nullptr);
  }
}
