#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include <xenia/base/mutex.h>

#include "kobject.hpp"

namespace uplift
{
  class ObjectTable
  {
  public:
    ObjectTable();
    ~ObjectTable();

    void Reset();

    uint32_t AddHandle(objects::Object* object, HANDLE* out_handle);
    uint32_t DuplicateHandle(HANDLE handle, HANDLE* out_handle);
    uint32_t RetainHandle(HANDLE handle);
    uint32_t ReleaseHandle(HANDLE handle);
    uint32_t RemoveHandle(HANDLE handle);

    object_ref<objects::Object> LookupObject(HANDLE handle)
    {
      auto object = LookupObject(handle, false);
      return object_ref<objects::Object>(reinterpret_cast<objects::Object*>(object));
    }

    template <typename T>
    object_ref<T> LookupObject(HANDLE handle)
    {
      auto object = LookupObject(handle, false);
      if (object)
      {
        assert_true(object->type() == T::ObjectType);
      }
      return object_ref<T>(reinterpret_cast<T*>(object));
    }

    uint32_t AddNameMapping(const std::string& name, HANDLE handle);
    void RemoveNameMapping(const std::string& name);
    uint32_t GetObjectByName(const std::string& name, HANDLE* out_handle);
    
    template <typename T>
    std::vector<object_ref<T>> GetObjectsByType(objects::Object::Type type)
    {
      std::vector<object_ref<T>> results;
      GetObjectsByType(type, reinterpret_cast<std::vector<object_ref<objects::Object>>*>(&results));
      return results;
    }

    template <typename T>
    std::vector<object_ref<T>> GetObjectsByType()
    {
      std::vector<object_ref<T>> results;
      GetObjectsByType(T::ObjectType, reinterpret_cast<std::vector<object_ref<objects::Object>>*>(&results));
      return results;
    }

    std::vector<object_ref<objects::Object>> GetAllObjects();
    void PurgeAllObjects();

  private:
    typedef struct
    {
      int handle_ref_count = 0;
      objects::Object* object = nullptr;
    }
    ObjectTableEntry;

    ObjectTableEntry* LookupTable(HANDLE handle);
    objects::Object* LookupObject(HANDLE handle, bool already_locked);
    void GetObjectsByType(objects::Object::Type type, std::vector<object_ref<objects::Object>>* results);

    HANDLE TranslateHandle(HANDLE handle);
    uint32_t FindFreeSlot(uint32_t* out_slot);
    bool Resize(uint32_t new_capacity);

    xe::global_critical_region global_critical_region_;
    uint32_t table_capacity_ = 0;
    ObjectTableEntry* table_ = nullptr;
    uint32_t last_free_entry_ = 0;
    std::unordered_map<std::string, HANDLE> name_table_;
  };

  // Generic lookup
  template <>
  object_ref<objects::Object> ObjectTable::LookupObject<objects::Object>(HANDLE handle);
}
