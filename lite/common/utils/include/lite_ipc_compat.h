/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * lite IPC compatibility layer (empty stubs only).
 * Provides the IPC type surface (sptr/wptr/IRemoteBroker/IRemoteStub/
 * IRemoteProxy/MessageParcel/RefBase) consumed by shared interface headers,
 * with no real IPC behavior: lite callbacks are in-process direct calls.
 * Policy: stub semantics only -- introducing real IPC here is forbidden.
 */

#ifndef LITE_IPC_COMPAT_H
#define LITE_IPC_COMPAT_H

#include <memory>

namespace OHOS {
class RefBase {
public:
    RefBase() = default;
    virtual ~RefBase() = default;
    void IncRef() {}
    void DecRef() {}
};

template <typename T>
class sptr {
public:
    sptr() = default;
    sptr(std::nullptr_t) {}
    sptr(T* p) : ptr_(p) {}
    sptr(const sptr<T>& other) : ptr_(other.ptr_) {}
    sptr(sptr<T>&& other) : ptr_(other.ptr_) { other.ptr_ = nullptr; }
    sptr<T>& operator=(const sptr<T>& other) { ptr_ = other.ptr_; return *this; }
    sptr<T>& operator=(sptr<T>&& other) { ptr_ = other.ptr_; other.ptr_ = nullptr; return *this; }
    sptr<T>& operator=(std::nullptr_t) { ptr_ = nullptr; return *this; }
    sptr<T>& operator=(T* p) { ptr_ = p; return *this; }
    T* operator->() const { return ptr_; }
    T& operator*() const { return *ptr_; }
    T* GetRefPtr() const { return ptr_; }
    explicit operator bool() const { return ptr_ != nullptr; }
    bool operator==(std::nullptr_t) const { return ptr_ == nullptr; }
    bool operator!=(std::nullptr_t) const { return ptr_ != nullptr; }
    bool operator==(const sptr<T>& other) const { return ptr_ == other.ptr_; }
    bool operator!=(const sptr<T>& other) const { return ptr_ != other.ptr_; }
private:
    T* ptr_ = nullptr;
};

template <typename T>
class wptr {
public:
    wptr() = default;
    wptr(std::nullptr_t) {}
    wptr(const sptr<T>& other) : ptr_(other.GetRefPtr()) {}
    wptr(T* p) : ptr_(p) {}
    sptr<T> promote() const { return sptr<T>(ptr_); }
    T* GetRefPtr() const { return ptr_; }
    explicit operator bool() const { return ptr_ != nullptr; }
private:
    T* ptr_ = nullptr;
};

class IRemoteObject;
class IRemoteBroker {
public:
    virtual ~IRemoteBroker() = default;
    virtual sptr<IRemoteObject> AsObject() { return nullptr; }
};

class IRemoteObject : public virtual RefBase {
public:
    virtual ~IRemoteObject() = default;
};

class IPCObjectStub : public virtual RefBase {
public:
    virtual ~IPCObjectStub() = default;
};

class MessageParcel {};
class MessageOption {};

#define DECLARE_INTERFACE_DESCRIPTOR(_desc)

template <typename INTERFACE>
class IRemoteStub : public INTERFACE, public IPCObjectStub {
public:
    IRemoteStub() = default;
    virtual ~IRemoteStub() = default;
};

template <typename INTERFACE>
class IRemoteProxy : public INTERFACE {
public:
    IRemoteProxy() = default;
    virtual ~IRemoteProxy() = default;
};

class SystemAbility : public virtual RefBase {
public:
    SystemAbility(int32_t id, bool runOnCreate = false) {}
    virtual ~SystemAbility() = default;
    virtual void OnStart() {}
    virtual void OnStop() {}
};

class IServiceRegistry : public virtual RefBase {
public:
    virtual ~IServiceRegistry() = default;
};
}

#endif
