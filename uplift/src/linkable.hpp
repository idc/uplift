#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <llvm/BinaryFormat/ELF.h>

#include "rip_zone.hpp"
#include "rip_pointers.hpp"

#include "program_info.hpp"
#include "dynamic_info.hpp"

namespace uplift
{
  class Loader;

  class Linkable
  {
  public:
    static std::unique_ptr<Linkable> Load(Loader* loader, const std::wstring& path);

    Linkable(Loader* loader, const std::wstring& path);
    virtual ~Linkable();

    std::wstring name() const { return name_; }
    uint32_t id() const { return id_; }
    uint16_t type() const { return type_; }
    bool has_dynamic() const { return dynamic_buffer_ != nullptr; }
    uint64_t sce_proc_param_address() const { return sce_proc_param_address_; }
    size_t sce_proc_param_size() const { return sce_proc_param_size_; }

    uint8_t* base_address() const { return base_address_; }
    void* entrypoint() const { return base_address_ ? &base_address_[entrypoint_] : nullptr; }

    ProgramInfo program_info() const { return program_info_; }
    DynamicInfo dynamic_info() const { return dynamic_info_; }

    void set_id(uint32_t id) { id_ = id; }
    void set_fsbase(void* fsbase);

    bool ResolveSymbol(uint32_t hash, const std::string& name, uint64_t& value);
    bool Relocate();

    void Protect();
    void Unprotect();

  private:
    void ProcessDynamic();
    void AnalyzeAndPatchCode();

    bool ResolveExternalSymbol(const std::string& local_name, uint64_t& value);

    bool RelocateRela();
    bool RelocatePltRela();

    Loader* loader_;
    std::wstring path_;
    std::wstring name_;
    uint32_t id_;
    llvm::ELF::Elf64_Half type_;
    uint8_t* dynamic_buffer_;
    size_t dynamic_size_;
    uint8_t* sce_dynlibdata_buffer_;
    size_t sce_dynlibdata_size_;
    uint8_t* sce_comment_buffer_;
    size_t sce_comment_size_;
    uint8_t* reserved_address_;
    size_t reserved_prefix_size_;
    size_t reserved_suffix_size_;
    uint8_t* base_address_;
    RIPPointers* rip_pointers_;
    RIPZone rip_zone_;
    uint64_t sce_proc_param_address_;
    uint64_t sce_proc_param_size_;
    uint64_t entrypoint_;
    std::vector<llvm::ELF::Elf64_Phdr> load_headers_;
    std::unordered_map<uint8_t*, uint8_t> interrupts_;
    ProgramInfo program_info_;
    DynamicInfo dynamic_info_;
  };
}
