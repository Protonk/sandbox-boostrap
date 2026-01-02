# macOS Seatbelt/Sandbox Trace Script

macOS sandbox profiles used to be able to include a `trace` command that would write all the denied operations to a sandbox profile, allowing a profile to be iterativley built up. Apple removed that functionality for reasons explained below.

`trace.sh` examines the kernel log for the denied operations and creates the relevant allow rules in a sandbox profile, just like the sandbox profile `trace` command used to.

`shrink.sh` tries to reduce a sandbox profile to the minimum lines necessary.

It's very rough and ready at the moment (check the sed regex'es in the script to see what I mean) and needs more testing with a wider set of use cases.

## Usage

`trace.sh <executable name> <sandbox profile>`

Will execute `executable name` with a deny all rule, record all the denied operations that occur during execution, then write the corresponding allow rule to the `sandbox profile`.

It will keep executing until there is a return code of 0, and build up the rule base. It will also stop if no new rules are added. This logic can be flawed. See the discussion below.

`shrink.sh <executable name> <sandbox profile>`

Will execute `executable name` with the sandbox profile provided, then attempt to remove each line and discard them if the command still executes.

As with trace, this will use a return code of 0 as indication of successful execution.

## Background

macOS contains a nuanced and detailed sandbox tool that used to be called seatbelt. macOS itself uses these profiles to constrain the execution of many internal services. You can see these at `/System/Library/Sandbox/Profiles`.

However, Apple don't want users writing these anymore. So they deprecated the utility for running executables with these sandbox scripts `sandbox-exec`. But, this hasn't impacted it's functioning yet, and given that Apple themselves still use these, and it's part of the underpinning of the App sandbox, the functionality is unlikely to go away.

Apple would instead like us to use the App sandbox. The problem with the App sandbox is two fold:

1. It requires a `.app` which is a real hassle for simple executables and scripts.
2. It moves everything into it's own filesystem container requiring an irritating copying/linking process.
3. Entitlements aren't able to constrain things as granularly as the sandbox profiles are.

Also, Apple states in various places that this is an internal API and likely to change. So even if you have a working sandbox profile, it could change from one version of macOS to the next. 

Finally, the profile language isn't documented anywhere, so the only way to discover what's needed is by doing this.

## Usage Considerations

### Stop condition

By default the stop condition is if no new rules are added or a return code of 0 is achieved. This might not be appropriate for your case and you'll need to edit the script (i.e. if the valid return code is 1).

### Temporary or Random files

If your executable writes to a temporary file or a file with a random filename, then every execution will generate a new literal path for that file. You'll need to stop the execution and change the `literal` to a `subpath` for the directory it's writing to instead.

### Shrinking

The kernel log will show denied operations that aren't mandatory for the program to execute. `shrink.sh` can be used to reduce the final profile to the minimum necessary.

### Commands that don't exit

Some commands, once running, don't exit. You can use trace.sh to get to the point of basic execution, but after that might need to manually kill the executable after testing additional functionality to get coverage for all the code paths. Tests or fuzzer's can help here.

### Sub-processes

This doesn't currently follow the execution of subprocesses (e.g. the exec*() series of functions from the stdc unistd.h). Rather run a new trace for those and include them in the master profile with the `(import "subprocess.sb")` sandbox profile command.
