#ifndef SYSCALL
#define SYSCALL(x,y,...)
#endif
SYSCALL(4, write, int fd, const void* buf, size_t nbytes);
SYSCALL(5, open, const char* path, int flags, uint64_t mode);
SYSCALL(6, close, int fd);
SYSCALL(20, getpid);
SYSCALL(54, ioctl, int fd, uint32_t request, void* argp);
SYSCALL(165, sysarch, int number, void* args);
SYSCALL(202, sysctl, int* name, uint32_t namelen, void* oldp, size_t* oldlenp, const void* newp, size_t newlen);
SYSCALL(340, sigprocmask);
SYSCALL(416, sigaction);
SYSCALL(432, thr_self, void** arg1);
SYSCALL(454, _umtx_op, void* obj, int op, uint32_t val, void* uaddr1, void* uaddr2);
SYSCALL(464, thr_set_name, long id, const char* name);
SYSCALL(466, rtprio_thread, int function, uint64_t lwpid, void* rtp);
SYSCALL(477, mmap, void* addr, size_t len, int prot, int flags, int fd, off_t offset);
SYSCALL(532, regmgr_call, uint32_t op, uint32_t id, void* result, void* value, uint64_t type);
SYSCALL(557, namedobj_create, const char* name, void* arg2, uint32_t arg3);
SYSCALL(587, get_authinfo, void* arg1, void* arg2);
SYSCALL(588, mname, uint8_t* arg1, size_t arg2, const char* name, void* arg4);
SYSCALL(591, dynlib_dlsym, uint32_t id, const char* name, void** sym);
SYSCALL(592, dynlib_get_list, void* arg1, void* arg2, size_t** arg3);
SYSCALL(594, dynlib_load_prx, const char* path, void* arg2, uint32_t* arg3, void* arg4);
SYSCALL(596, dynlib_do_copy_relocations);
SYSCALL(598, dynlib_get_proc_param, void** data_address, size_t* data_size);
SYSCALL(599, dynlib_process_needed_and_relocate);
SYSCALL(601, mdbg_service, void* arg1, void* arg2, void* arg3);
SYSCALL(602, randomized_path, const char* set_path, char* path, size_t* path_length);
SYSCALL(605, workaround8849);
SYSCALL(608, dynlib_get_info_ex, uint32_t id, void* arg2, void* arg3);
SYSCALL(610, eport_create, /*const char* arg1,*/ uint32_t arg2);
SYSCALL(612, get_proc_type_info, void* type_info);
SYSCALL(622, ipmimgr_call);
