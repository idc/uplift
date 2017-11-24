#pragma once

#include <string>
#include <vector>

#include <llvm/BinaryFormat/ELF.h>

namespace uplift
{
  struct ModuleInfo
  {
    std::string name;
    union
    {
      uint64_t value;
      struct
      {
        uint32_t name_offset;
        uint8_t version_minor;
        uint8_t version_major;
        uint8_t id;
      };
    };
    uint16_t attributes;
  };

  struct LibraryInfo
  {
    std::string name;
    union
    {
      uint64_t value;
      struct
      {
        uint32_t name_offset;
        uint16_t version;
        uint16_t id;
      };
    };
    uint16_t attributes;
    bool is_export;
  };

  struct DynamicInfo
  {
    llvm::ELF::Elf64_Xword rela_table_offset;
    llvm::ELF::Elf64_Xword rela_table_size;
    llvm::ELF::Elf64_Xword pltrela_table_offset;
    llvm::ELF::Elf64_Xword pltrela_table_size;
    llvm::ELF::Elf64_Xword string_table_offset;
    llvm::ELF::Elf64_Xword string_table_size;
    llvm::ELF::Elf64_Xword symbol_table_offset;
    llvm::ELF::Elf64_Xword symbol_table_size;
    llvm::ELF::Elf64_Xword hash_table_offset;
    llvm::ELF::Elf64_Xword hash_table_size;

    uint64_t flags;
    uint64_t flags_1;
    std::vector<std::string> shared_object_names;
    std::string shared_object_name;
    std::vector<ModuleInfo> modules;
    std::vector<LibraryInfo> libraries;
    llvm::ELF::Elf64_Xword pltgot_offset;
    llvm::ELF::Elf64_Xword init_offset;
    llvm::ELF::Elf64_Xword fini_offset;
    uint8_t	fingerprint[20];
    std::string output_image_name;

    bool find_module(uint16_t id, ModuleInfo& info);
    bool find_library(uint16_t id, LibraryInfo& info);
  };

  bool get_dynamic_info(llvm::ELF::Elf64_Dyn* entry, size_t entry_count, uint8_t* data_buffer, size_t data_size, DynamicInfo& info);
}
