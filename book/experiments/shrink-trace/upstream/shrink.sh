#!/bin/bash

# Rough and ready macOS seatbelt/sandbox profile shrinker - removes unnecessary lines
# by @singe

# Path to the sandbox profile
SANDBOX_PROFILE="$2"
# Temporary sandbox profile used for testing
TEMP_SANDBOX_PROFILE=$(mktemp)
# The command to run in the sandbox
COMMAND="$1"

# Check the full sandbox first
sandbox-exec -f $SANDBOX_PROFILE $COMMAND
if [ $? -ne 0 ]; then
    echo "[+] The command could not execute successfully with the initial sandbox profile provided."
    exit 1
else
    echo "[*] Successful execution of the command with initial sandbox."
fi

# Read each line from the sandbox file, excluding the first two lines
LINE_COUNT=$(wc -l < "$SANDBOX_PROFILE")
cp $SANDBOX_PROFILE $TEMP_SANDBOX_PROFILE

# Loop through each line starting from the bottom (so as not to mess up line numbers when we modify the file)
# This will remove the (version 1) line too, because we can't be sure it's the
#     first line if there are comments above it
for (( i=$LINE_COUNT; i>0; i-- ))
do
    TMP=$(mktemp)

    # Create a new sandbox profile without the current line, but include the first two lines
    sed "${i}d" "$TEMP_SANDBOX_PROFILE" > $TMP
    LINE="$(sed "${i}q;d" $SANDBOX_PROFILE)"

    echo "[-] Attempting to remove line $i: $LINE"

    # Test the command with the modified sandbox profile
    echo "[-] Executing ..."
    sandbox-exec -f "$TMP" $COMMAND

    if [ $? -eq 0 ]; then
        echo $LINE | grep "([ ]*deny " > /dev/null
        if [[ $? -eq 0 ]]; then
            # Command successful but we removed a deny rule so put it back
            echo "[*] Not removing a deny rule"
        else
            # Command successful without the rule, so we remove it permanently
            echo "[+] Removed line $i: unnecessary rule."
            cp $TMP $TEMP_SANDBOX_PROFILE
        fi
    else
        # Command failed without the rule, keep the rule
        echo "[*] Kept line $i: necessary rule."
    fi
done

# Output the minimized sandbox profile
echo "[-] Minimised sandbox profile:"
cat $TEMP_SANDBOX_PROFILE
mv $TEMP_SANDBOX_PROFILE $SANDBOX_PROFILE.shrunk
