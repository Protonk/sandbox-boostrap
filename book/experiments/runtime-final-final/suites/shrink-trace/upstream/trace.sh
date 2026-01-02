#!/bin/bash

# Rough and ready macOS seatbelt/sandbox profile creator
# by @singe

# Enable job control
set -m

# Define your program name and sandbox profile path
PROGRAM_NAME="$1"
SANDBOX_PROFILE="$2"
LOG_FILE="sandbox_log.txt"
PROGRAM_PID=0
RETURN_CODE=9999
RULE_LENGTH=0
done=false

# Create the initial sandbox profile
if [[ ! -f "$SANDBOX_PROFILE" ]]; then
    echo "(version 1)
    (deny default)" > $SANDBOX_PROFILE
fi

# Function to run the program in the sandbox and log events
run_program() {
    # Monitor sandbox events specifically for this program
    echo [-] Starting logging ...
    log stream --style compact --info --debug --predicate "((processID == 0) AND (senderImagePath CONTAINS '/Sandbox'))" > $LOG_FILE &
    sleep 2
    LOG_PID=$!

    # Run the program in sandbox mode
    echo [-] Executing program
    sandbox-exec -f $SANDBOX_PROFILE $PROGRAM_NAME &
    PROGRAM_PID=$!

    # Wait for the program to finish
    wait $PROGRAM_PID
    RETURN_CODE=$?
    echo [-] Finished executing. Stopping logging.
    sleep 5
    kill $LOG_PID
}

# Function to update the sandbox profile from log events
update_sandbox_profile() {

    OLD_LENGTH=$RULE_LENGTH
    grep -a -e "deny" $LOG_FILE | grep -a -e "($PROGRAM_PID)" | while read -r line; do
        # Extract service and operation from the log line
          # 1 - transform log line into allow rule with literal
          # 2 - convert sysctl lines to use sysctl-name not literal
          # 3 - convert ioctil path: to just the path
          # 4 - convert literal in network rules to local ip - this is a bad
          #     assumption and needs to be tested with remote ips
          # 5 - convert network local:* to localhost
          # 6 - convert rules that take no parameters
          # 7 - convert mach-lookup rules to use global-name instead of literal
          # 8 - why would a network line have a file path in it? It happens for
          #     some reason. Binding it to a random port on localhost.
        rule=$(echo $line \
            | sed "s/.* deny([0-9]*) \([^ ]*\) \([^ ]*\).*$/\(allow \1 (literal \"\2\"))/" \
            | sed "s/sysctl-\(.*\) (literal /sysctl-\1 (sysctl-name /" \
            | sed "s/\"path:/\"/" \
            | sed "s/network-\(.*\) (literal /network-\1 (local ip /" \
            | sed "s/\"local:\*/\"localhost/" \
            | sed "s/.* deny([0-9]*) \([^ ]*\)/\(allow \1)/" \
            | sed "s/mach-lookup (literal /mach-lookup (global-name /" \
            | sed "s/network-\([^ ]*\) (local ip \"\/.*\"/network-\1 (local ip \"localhost:2000\"/" \
        )
      
        # Check if rule exists already
        grep "$rule" $SANDBOX_PROFILE > /dev/null
        if [[ $? -ne 0 ]]; then 
            # Append the corresponding allow rule to the sandbox profile
            echo [+] New rule, adding to profile.
            echo "$rule" >> $SANDBOX_PROFILE
        else
            echo [*] Duplicate rule, not adding.
        fi
    done

    # Check if we've added any rules
    RULE_LENGTH=$(wc -l $SANDBOX_PROFILE)
    if [[ $RULE_LENGTH == $OLD_LENGTH ]]; then
        done=true
        echo [*] No new rules added, exiting.
    fi
    
}


# Run the functions and loop until exit code is 0 or no new rules added
while [[ "$done" == "false" ]]; do
  run_program
  update_sandbox_profile
  if [[ $RETURN_CODE -eq 0 ]]; then
      echo [+] Return code is 0, stopping execution loop.
      done=true
  fi
done

killall $PROGRAM_NAME
killall log

echo "Updated sandbox profile:"
cat $SANDBOX_PROFILE
