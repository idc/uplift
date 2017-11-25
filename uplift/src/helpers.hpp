#pragma once

#include <string>

#include <llvm/BinaryFormat/ELF.h>

#include <xenia/base/memory.h>

namespace uplift
{
  constexpr size_t align_size_const(size_t size, size_t align)
  {
    const size_t padding = align - 1;
    const size_t mask = ~padding;
    return (size + padding) & mask;
  }

  size_t __forceinline align_size(size_t size, const size_t align)
  {
    const size_t padding = align - 1;
    const size_t mask = ~padding;
    return (size + padding) & mask;
  }

  xe::memory::PageAccess get_page_access(llvm::ELF::Elf64_Word flags);
  
  bool get_text_region(uint8_t* buffer, size_t buffer_size, uint8_t*& text, size_t& text_size);

  bool parse_symbol_name(const std::string& buffer, std::string& name, uint16_t& library_id, uint16_t& module_id);

  uint32_t elf_hash(const char* name);
}
