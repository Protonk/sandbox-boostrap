#pragma D option quiet

/*
 * Broad xattr hook scan for a single traced process.
 * Usage: sudo dtrace -q -s scan_xattr_hooks.d -c "<xattr command>"
 */

fbt:mach_kernel:mac_*xattr*:entry
/pid == $target/
{
    printf("EVENT kind=scan_xattr hook=%s pid=%d exec=%s ts=%llu\n",
        probefunc, pid, execname, (unsigned long long)timestamp);
}
