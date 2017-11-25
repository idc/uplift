#include "stdafx.h"

#include <xenia/base/assert.h>

#include "loader.hpp"
#include "kobject.hpp"

using namespace uplift;
using namespace uplift::objects;

Object::Object(Loader* loader, Type type)
  : loader_(loader)
  , handles_()
  , pointer_ref_count_(1)
  , type_(type)
{
  handles_.reserve(10);
  loader->object_table()->AddHandle(this, nullptr);
}

Object::~Object()
{
  assert_zero(pointer_ref_count_);
}

void Object::RetainHandle() 
{
  loader_->object_table()->RetainHandle(handles_[0]);
}

bool Object::ReleaseHandle()
{
  return loader_->object_table()->ReleaseHandle(handles_[0]);
}

void Object::Retain() { ++pointer_ref_count_; }

void Object::Release()
{
  if (--pointer_ref_count_ == 0)
  {
    delete this;
  }
}

uint32_t Object::Delete()
{
  if (!name_.empty())
  {
    loader_->object_table()->RemoveNameMapping(name_);
  }
  return loader_->object_table()->RemoveHandle(handles_[0]);
}
