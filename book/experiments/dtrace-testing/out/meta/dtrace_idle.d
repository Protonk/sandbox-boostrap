#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option dynvarsize=16m
#pragma D option strsize=2048
inline string PHASE = "idle";
inline int ERR_EPERM = 1;
inline int ERR_EACCES = 13;

/* open/open_nocancel */
syscall::open:entry
/pid == $target/
{
    self->sys = probefunc;
    self->path = copyinstr(arg0);
    self->path2 = "";
    self->flags = (int)arg1;
    self->mode = (int)arg2;
    self->dirfd = -1;
    self->newdirfd = -1;
}
syscall::open:return
/pid == $target/
{
    this->err = errno;
    if (this->err == ERR_EPERM || this->err == ERR_EACCES) {
        printf("{\"phase\":\"%s\",\"kind\":\"syscall\",\"ts_ns\":%llu,\"pid\":%d,\"execname\":\"%s\",\"name\":\"%s\",\"path\":\"%s\",\"path2\":\"%s\",\"flags\":%d,\"mode\":%d,\"dirfd\":%d,\"newdirfd\":%d,\"ret\":%d,\"errno\":%d}\n",

            PHASE, walltimestamp, pid, execname, self->sys, self->path, self->path2, self->flags, self->mode, self->dirfd, self->newdirfd, (int)arg0, this->err);
    }
    self->sys = 0;
    self->path = 0;
    self->path2 = 0;
    self->flags = 0;
    self->mode = 0;
    self->dirfd = 0;
    self->newdirfd = 0;
}

syscall::open_nocancel:entry
/pid == $target/
{
    self->sys = probefunc;
    self->path = copyinstr(arg0);
    self->path2 = "";
    self->flags = (int)arg1;
    self->mode = (int)arg2;
    self->dirfd = -1;
    self->newdirfd = -1;
}
syscall::open_nocancel:return
/pid == $target/
{
    this->err = errno;
    if (this->err == ERR_EPERM || this->err == ERR_EACCES) {
        printf("{\"phase\":\"%s\",\"kind\":\"syscall\",\"ts_ns\":%llu,\"pid\":%d,\"execname\":\"%s\",\"name\":\"%s\",\"path\":\"%s\",\"path2\":\"%s\",\"flags\":%d,\"mode\":%d,\"dirfd\":%d,\"newdirfd\":%d,\"ret\":%d,\"errno\":%d}\n",

            PHASE, walltimestamp, pid, execname, self->sys, self->path, self->path2, self->flags, self->mode, self->dirfd, self->newdirfd, (int)arg0, this->err);
    }
    self->sys = 0;
    self->path = 0;
    self->path2 = 0;
    self->flags = 0;
    self->mode = 0;
    self->dirfd = 0;
    self->newdirfd = 0;
}

/* openat/openat_nocancel */
syscall::openat*:entry
/pid == $target/
{
    self->sys = probefunc;
    self->path = copyinstr(arg1);
    self->path2 = "";
    self->flags = (int)arg2;
    self->mode = (int)arg3;
    self->dirfd = (int)arg0;
    self->newdirfd = -1;
}
syscall::openat*:return
/pid == $target/
{
    this->err = errno;
    if (this->err == ERR_EPERM || this->err == ERR_EACCES) {
        printf("{\"phase\":\"%s\",\"kind\":\"syscall\",\"ts_ns\":%llu,\"pid\":%d,\"execname\":\"%s\",\"name\":\"%s\",\"path\":\"%s\",\"path2\":\"%s\",\"flags\":%d,\"mode\":%d,\"dirfd\":%d,\"newdirfd\":%d,\"ret\":%d,\"errno\":%d}\n",

            PHASE, walltimestamp, pid, execname, self->sys, self->path, self->path2, self->flags, self->mode, self->dirfd, self->newdirfd, (int)arg0, this->err);
    }
    self->sys = 0;
    self->path = 0;
    self->path2 = 0;
    self->flags = 0;
    self->mode = 0;
    self->dirfd = 0;
    self->newdirfd = 0;
}

/* stat/lstat */
syscall::stat:entry
/pid == $target/
{
    self->sys = probefunc;
    self->path = copyinstr(arg0);
    self->path2 = "";
    self->flags = -1;
    self->mode = -1;
    self->dirfd = -1;
    self->newdirfd = -1;
}
syscall::stat:return
/pid == $target/
{
    this->err = errno;
    if (this->err == ERR_EPERM || this->err == ERR_EACCES) {
        printf("{\"phase\":\"%s\",\"kind\":\"syscall\",\"ts_ns\":%llu,\"pid\":%d,\"execname\":\"%s\",\"name\":\"%s\",\"path\":\"%s\",\"path2\":\"%s\",\"flags\":%d,\"mode\":%d,\"dirfd\":%d,\"newdirfd\":%d,\"ret\":%d,\"errno\":%d}\n",

            PHASE, walltimestamp, pid, execname, self->sys, self->path, self->path2, self->flags, self->mode, self->dirfd, self->newdirfd, (int)arg0, this->err);
    }
    self->sys = 0;
    self->path = 0;
    self->path2 = 0;
    self->flags = 0;
    self->mode = 0;
    self->dirfd = 0;
    self->newdirfd = 0;
}

syscall::lstat:entry
/pid == $target/
{
    self->sys = probefunc;
    self->path = copyinstr(arg0);
    self->path2 = "";
    self->flags = -1;
    self->mode = -1;
    self->dirfd = -1;
    self->newdirfd = -1;
}
syscall::lstat:return
/pid == $target/
{
    this->err = errno;
    if (this->err == ERR_EPERM || this->err == ERR_EACCES) {
        printf("{\"phase\":\"%s\",\"kind\":\"syscall\",\"ts_ns\":%llu,\"pid\":%d,\"execname\":\"%s\",\"name\":\"%s\",\"path\":\"%s\",\"path2\":\"%s\",\"flags\":%d,\"mode\":%d,\"dirfd\":%d,\"newdirfd\":%d,\"ret\":%d,\"errno\":%d}\n",

            PHASE, walltimestamp, pid, execname, self->sys, self->path, self->path2, self->flags, self->mode, self->dirfd, self->newdirfd, (int)arg0, this->err);
    }
    self->sys = 0;
    self->path = 0;
    self->path2 = 0;
    self->flags = 0;
    self->mode = 0;
    self->dirfd = 0;
    self->newdirfd = 0;
}

syscall::stat64:entry
/pid == $target/
{
    self->sys = probefunc;
    self->path = copyinstr(arg0);
    self->path2 = "";
    self->flags = -1;
    self->mode = -1;
    self->dirfd = -1;
    self->newdirfd = -1;
}
syscall::stat64:return
/pid == $target/
{
    this->err = errno;
    if (this->err == ERR_EPERM || this->err == ERR_EACCES) {
        printf("{\"phase\":\"%s\",\"kind\":\"syscall\",\"ts_ns\":%llu,\"pid\":%d,\"execname\":\"%s\",\"name\":\"%s\",\"path\":\"%s\",\"path2\":\"%s\",\"flags\":%d,\"mode\":%d,\"dirfd\":%d,\"newdirfd\":%d,\"ret\":%d,\"errno\":%d}\n",

            PHASE, walltimestamp, pid, execname, self->sys, self->path, self->path2, self->flags, self->mode, self->dirfd, self->newdirfd, (int)arg0, this->err);
    }
    self->sys = 0;
    self->path = 0;
    self->path2 = 0;
    self->flags = 0;
    self->mode = 0;
    self->dirfd = 0;
    self->newdirfd = 0;
}

syscall::lstat64:entry
/pid == $target/
{
    self->sys = probefunc;
    self->path = copyinstr(arg0);
    self->path2 = "";
    self->flags = -1;
    self->mode = -1;
    self->dirfd = -1;
    self->newdirfd = -1;
}
syscall::lstat64:return
/pid == $target/
{
    this->err = errno;
    if (this->err == ERR_EPERM || this->err == ERR_EACCES) {
        printf("{\"phase\":\"%s\",\"kind\":\"syscall\",\"ts_ns\":%llu,\"pid\":%d,\"execname\":\"%s\",\"name\":\"%s\",\"path\":\"%s\",\"path2\":\"%s\",\"flags\":%d,\"mode\":%d,\"dirfd\":%d,\"newdirfd\":%d,\"ret\":%d,\"errno\":%d}\n",

            PHASE, walltimestamp, pid, execname, self->sys, self->path, self->path2, self->flags, self->mode, self->dirfd, self->newdirfd, (int)arg0, this->err);
    }
    self->sys = 0;
    self->path = 0;
    self->path2 = 0;
    self->flags = 0;
    self->mode = 0;
    self->dirfd = 0;
    self->newdirfd = 0;
}

/* access */
syscall::access:entry
/pid == $target/
{
    self->sys = probefunc;
    self->path = copyinstr(arg0);
    self->path2 = "";
    self->flags = (int)arg1;
    self->mode = -1;
    self->dirfd = -1;
    self->newdirfd = -1;
}
syscall::access:return
/pid == $target/
{
    this->err = errno;
    if (this->err == ERR_EPERM || this->err == ERR_EACCES) {
        printf("{\"phase\":\"%s\",\"kind\":\"syscall\",\"ts_ns\":%llu,\"pid\":%d,\"execname\":\"%s\",\"name\":\"%s\",\"path\":\"%s\",\"path2\":\"%s\",\"flags\":%d,\"mode\":%d,\"dirfd\":%d,\"newdirfd\":%d,\"ret\":%d,\"errno\":%d}\n",

            PHASE, walltimestamp, pid, execname, self->sys, self->path, self->path2, self->flags, self->mode, self->dirfd, self->newdirfd, (int)arg0, this->err);
    }
    self->sys = 0;
    self->path = 0;
    self->path2 = 0;
    self->flags = 0;
    self->mode = 0;
    self->dirfd = 0;
    self->newdirfd = 0;
}

/* unlink/unlinkat */
syscall::unlink:entry
/pid == $target/
{
    self->sys = probefunc;
    self->path = copyinstr(arg0);
    self->path2 = "";
    self->flags = -1;
    self->mode = -1;
    self->dirfd = -1;
    self->newdirfd = -1;
}
syscall::unlink:return
/pid == $target/
{
    this->err = errno;
    if (this->err == ERR_EPERM || this->err == ERR_EACCES) {
        printf("{\"phase\":\"%s\",\"kind\":\"syscall\",\"ts_ns\":%llu,\"pid\":%d,\"execname\":\"%s\",\"name\":\"%s\",\"path\":\"%s\",\"path2\":\"%s\",\"flags\":%d,\"mode\":%d,\"dirfd\":%d,\"newdirfd\":%d,\"ret\":%d,\"errno\":%d}\n",

            PHASE, walltimestamp, pid, execname, self->sys, self->path, self->path2, self->flags, self->mode, self->dirfd, self->newdirfd, (int)arg0, this->err);
    }
    self->sys = 0;
    self->path = 0;
    self->path2 = 0;
    self->flags = 0;
    self->mode = 0;
    self->dirfd = 0;
    self->newdirfd = 0;
}

syscall::unlinkat:entry
/pid == $target/
{
    self->sys = probefunc;
    self->path = copyinstr(arg1);
    self->path2 = "";
    self->flags = (int)arg2;
    self->mode = -1;
    self->dirfd = (int)arg0;
    self->newdirfd = -1;
}
syscall::unlinkat:return
/pid == $target/
{
    this->err = errno;
    if (this->err == ERR_EPERM || this->err == ERR_EACCES) {
        printf("{\"phase\":\"%s\",\"kind\":\"syscall\",\"ts_ns\":%llu,\"pid\":%d,\"execname\":\"%s\",\"name\":\"%s\",\"path\":\"%s\",\"path2\":\"%s\",\"flags\":%d,\"mode\":%d,\"dirfd\":%d,\"newdirfd\":%d,\"ret\":%d,\"errno\":%d}\n",

            PHASE, walltimestamp, pid, execname, self->sys, self->path, self->path2, self->flags, self->mode, self->dirfd, self->newdirfd, (int)arg0, this->err);
    }
    self->sys = 0;
    self->path = 0;
    self->path2 = 0;
    self->flags = 0;
    self->mode = 0;
    self->dirfd = 0;
    self->newdirfd = 0;
}

/* rename/renameat */
syscall::rename:entry
/pid == $target/
{
    self->sys = probefunc;
    self->path = copyinstr(arg0);
    self->path2 = copyinstr(arg1);
    self->flags = -1;
    self->mode = -1;
    self->dirfd = -1;
    self->newdirfd = -1;
}
syscall::rename:return
/pid == $target/
{
    this->err = errno;
    if (this->err == ERR_EPERM || this->err == ERR_EACCES) {
        printf("{\"phase\":\"%s\",\"kind\":\"syscall\",\"ts_ns\":%llu,\"pid\":%d,\"execname\":\"%s\",\"name\":\"%s\",\"path\":\"%s\",\"path2\":\"%s\",\"flags\":%d,\"mode\":%d,\"dirfd\":%d,\"newdirfd\":%d,\"ret\":%d,\"errno\":%d}\n",

            PHASE, walltimestamp, pid, execname, self->sys, self->path, self->path2, self->flags, self->mode, self->dirfd, self->newdirfd, (int)arg0, this->err);
    }
    self->sys = 0;
    self->path = 0;
    self->path2 = 0;
    self->flags = 0;
    self->mode = 0;
    self->dirfd = 0;
    self->newdirfd = 0;
}

syscall::renameat:entry
/pid == $target/
{
    self->sys = probefunc;
    self->path = copyinstr(arg1);
    self->path2 = copyinstr(arg3);
    self->flags = -1;
    self->mode = -1;
    self->dirfd = (int)arg0;
    self->newdirfd = (int)arg2;
}
syscall::renameat:return
/pid == $target/
{
    this->err = errno;
    if (this->err == ERR_EPERM || this->err == ERR_EACCES) {
        printf("{\"phase\":\"%s\",\"kind\":\"syscall\",\"ts_ns\":%llu,\"pid\":%d,\"execname\":\"%s\",\"name\":\"%s\",\"path\":\"%s\",\"path2\":\"%s\",\"flags\":%d,\"mode\":%d,\"dirfd\":%d,\"newdirfd\":%d,\"ret\":%d,\"errno\":%d}\n",

            PHASE, walltimestamp, pid, execname, self->sys, self->path, self->path2, self->flags, self->mode, self->dirfd, self->newdirfd, (int)arg0, this->err);
    }
    self->sys = 0;
    self->path = 0;
    self->path2 = 0;
    self->flags = 0;
    self->mode = 0;
    self->dirfd = 0;
    self->newdirfd = 0;
}

/* mkdir/mkdirat */
syscall::mkdir:entry
/pid == $target/
{
    self->sys = probefunc;
    self->path = copyinstr(arg0);
    self->path2 = "";
    self->flags = -1;
    self->mode = (int)arg1;
    self->dirfd = -1;
    self->newdirfd = -1;
}
syscall::mkdir:return
/pid == $target/
{
    this->err = errno;
    if (this->err == ERR_EPERM || this->err == ERR_EACCES) {
        printf("{\"phase\":\"%s\",\"kind\":\"syscall\",\"ts_ns\":%llu,\"pid\":%d,\"execname\":\"%s\",\"name\":\"%s\",\"path\":\"%s\",\"path2\":\"%s\",\"flags\":%d,\"mode\":%d,\"dirfd\":%d,\"newdirfd\":%d,\"ret\":%d,\"errno\":%d}\n",

            PHASE, walltimestamp, pid, execname, self->sys, self->path, self->path2, self->flags, self->mode, self->dirfd, self->newdirfd, (int)arg0, this->err);
    }
    self->sys = 0;
    self->path = 0;
    self->path2 = 0;
    self->flags = 0;
    self->mode = 0;
    self->dirfd = 0;
    self->newdirfd = 0;
}

syscall::mkdirat:entry
/pid == $target/
{
    self->sys = probefunc;
    self->path = copyinstr(arg1);
    self->path2 = "";
    self->flags = -1;
    self->mode = (int)arg2;
    self->dirfd = (int)arg0;
    self->newdirfd = -1;
}
syscall::mkdirat:return
/pid == $target/
{
    this->err = errno;
    if (this->err == ERR_EPERM || this->err == ERR_EACCES) {
        printf("{\"phase\":\"%s\",\"kind\":\"syscall\",\"ts_ns\":%llu,\"pid\":%d,\"execname\":\"%s\",\"name\":\"%s\",\"path\":\"%s\",\"path2\":\"%s\",\"flags\":%d,\"mode\":%d,\"dirfd\":%d,\"newdirfd\":%d,\"ret\":%d,\"errno\":%d}\n",

            PHASE, walltimestamp, pid, execname, self->sys, self->path, self->path2, self->flags, self->mode, self->dirfd, self->newdirfd, (int)arg0, this->err);
    }
    self->sys = 0;
    self->path = 0;
    self->path2 = 0;
    self->flags = 0;
    self->mode = 0;
    self->dirfd = 0;
    self->newdirfd = 0;
}

/* rmdir */
syscall::rmdir:entry
/pid == $target/
{
    self->sys = probefunc;
    self->path = copyinstr(arg0);
    self->path2 = "";
    self->flags = -1;
    self->mode = -1;
    self->dirfd = -1;
    self->newdirfd = -1;
}
syscall::rmdir:return
/pid == $target/
{
    this->err = errno;
    if (this->err == ERR_EPERM || this->err == ERR_EACCES) {
        printf("{\"phase\":\"%s\",\"kind\":\"syscall\",\"ts_ns\":%llu,\"pid\":%d,\"execname\":\"%s\",\"name\":\"%s\",\"path\":\"%s\",\"path2\":\"%s\",\"flags\":%d,\"mode\":%d,\"dirfd\":%d,\"newdirfd\":%d,\"ret\":%d,\"errno\":%d}\n",

            PHASE, walltimestamp, pid, execname, self->sys, self->path, self->path2, self->flags, self->mode, self->dirfd, self->newdirfd, (int)arg0, this->err);
    }
    self->sys = 0;
    self->path = 0;
    self->path2 = 0;
    self->flags = 0;
    self->mode = 0;
    self->dirfd = 0;
    self->newdirfd = 0;
}

/* sandbox_check */
pid$target::sandbox_check:entry
/pid == $target/
{
    self->sb_name = probefunc;
    self->sb_op = "";
    if (arg1 != 0) {
        self->sb_op = copyinstr(arg1);
    }
    self->sb_type = (int)arg2;
}
pid$target::sandbox_check:return
/pid == $target/
{
    this->err = errno;
    if (this->err == ERR_EPERM || this->err == ERR_EACCES) {
        printf("{\"phase\":\"%s\",\"kind\":\"sandbox_api\",\"ts_ns\":%llu,\"pid\":%d,\"execname\":\"%s\",\"name\":\"%s\",\"op\":\"%s\",\"type\":%d,\"ret\":%d,\"errno\":%d}\n",

            PHASE, walltimestamp, pid, execname, self->sb_name, self->sb_op, self->sb_type, (int)arg0, this->err);
    }
    self->sb_name = 0;
    self->sb_op = 0;
    self->sb_type = 0;
}

/* sandbox_init */
pid$target::sandbox_init:entry
/pid == $target/
{
    self->sb_name = probefunc;
    self->sb_profile = "";
    if (arg0 != 0) {
        self->sb_profile = copyinstr(arg0);
    }
    self->sb_flags = (unsigned long long)arg1;
}
pid$target::sandbox_init:return
/pid == $target/
{
    this->err = errno;
    if (this->err == ERR_EPERM || this->err == ERR_EACCES) {
        printf("{\"phase\":\"%s\",\"kind\":\"sandbox_api\",\"ts_ns\":%llu,\"pid\":%d,\"execname\":\"%s\",\"name\":\"%s\",\"profile\":\"%s\",\"flags\":%llu,\"ret\":%d,\"errno\":%d}\n",

            PHASE, walltimestamp, pid, execname, self->sb_name, self->sb_profile, self->sb_flags, (int)arg0, this->err);
    }
    self->sb_name = 0;
    self->sb_profile = 0;
    self->sb_flags = 0;
}

/* sandbox_apply */
pid$target::sandbox_apply:entry
/pid == $target/
{
    self->sb_name = probefunc;
    self->sb_policy = (unsigned long long)arg0;
}
pid$target::sandbox_apply:return
/pid == $target/
{
    this->err = errno;
    if (this->err == ERR_EPERM || this->err == ERR_EACCES) {
        printf("{\"phase\":\"%s\",\"kind\":\"sandbox_api\",\"ts_ns\":%llu,\"pid\":%d,\"execname\":\"%s\",\"name\":\"%s\",\"policy_ptr\":%llu,\"ret\":%d,\"errno\":%d}\n",

            PHASE, walltimestamp, pid, execname, self->sb_name, self->sb_policy, (int)arg0, this->err);
    }
    self->sb_name = 0;
    self->sb_policy = 0;
}
