#pragma D option quiet
fbt:mach_kernel:mac_policy_register:entry
{
    printf("EVENT target_symbol=%s mpc=%p handlep=%p xd=%p\n", probefunc, arg0, arg1, arg2);
    exit(0);
}
