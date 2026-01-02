#pragma D option quiet
inline string WORLD_ID = "sonoma-14.6.1-debug-vm";
inline string RUN_ID = "macf_setxattr_test";
fbt:mach_kernel:mac_vnode_check_open:entry
/pid == $target/
{
    this->ts = timestamp;
    printf("EVENT kind=hook hook=mac_vnode_check_open world=%s run_id=%s pid=%d tid=%d exec=%s ts=%llu ctx=0x%p vp=0x%p acc_mode=%d\n",
        WORLD_ID, RUN_ID, pid, tid, execname, this->ts, (void *)arg0, (void *)arg1, (int)arg2);
    
}
fbt:mach_kernel:mac_vnop_setxattr:entry
/pid == $target/
{
    this->ts = timestamp;
    printf("EVENT kind=hook hook=mac_vnop_setxattr world=%s run_id=%s pid=%d tid=%d exec=%s ts=%llu vp=0x%p name_ptr=0x%p buf_ptr=0x%p len=%llu\n",
        WORLD_ID, RUN_ID, pid, tid, execname, this->ts, (void *)arg0, (void *)arg1, (void *)arg2, (unsigned long long)arg3);
    
}
syscall::open*:entry
/pid == $target/
{
    this->ts = timestamp;
    printf("EVENT kind=syscall sys=open world=%s run_id=%s pid=%d tid=%d exec=%s ts=%llu path=%s flags=0x%x\n",
        WORLD_ID, RUN_ID, pid, tid, execname, this->ts, copyinstr(arg0), (int)arg1);
}

syscall::setxattr:entry
/pid == $target/
{
    this->ts = timestamp;
    printf("EVENT kind=syscall sys=setxattr world=%s run_id=%s pid=%d tid=%d exec=%s ts=%llu path=%s name=%s size=%llu\n",
        WORLD_ID, RUN_ID, pid, tid, execname, this->ts, copyinstr(arg0), copyinstr(arg1), (unsigned long long)arg4);
}

syscall::fsetxattr:entry
/pid == $target/
{
    this->ts = timestamp;
    printf("EVENT kind=syscall sys=fsetxattr world=%s run_id=%s pid=%d tid=%d exec=%s ts=%llu fd=%d name=%s size=%llu\n",
        WORLD_ID, RUN_ID, pid, tid, execname, this->ts, (int)arg0, copyinstr(arg1), (unsigned long long)arg4);
}
