#!/bin/bash

# "sys_exit" # causes async_shutdown to block indefinitely
# "socket_shutdown" # causes broken pipe
# "server_close"  # proper shutdown of the server
# "transport_close"  # close the transport directly
close_modes=("sys_exit" "socket_shutdown" "server_close" "transport_close")
# close_modes=("socket_shutdown")

cleanup() {
    if ps -p $PYTHON_PID > /dev/null; then
        kill $PYTHON_PID
    fi
}

# trap any exit signal (including script failure) to run the cleanup function
trap cleanup EXIT

for close_mode in "${close_modes[@]}"; do
    echo "============================================================================"
    echo "Running test_close with close_mode = $close_mode"

    # Create a temporary file for capturing output
    temp_output=$(mktemp)

    # Run the Python file in the background and redirect output to the temporary file
    python3 test_close.py $close_mode > "$temp_output" 2>&1 &

    # Get the PID of the Python process
    PYTHON_PID=$!

    sleep 1

    # Get the PID of the Python process
    PYTHON_PID=$!

    pushd ../out/build/gcc_debug/tests/ > /dev/null
    ./test_close_AsioSocket
    popd > /dev/null

    echo "--------------------------------------------------------"
    echo "Python websocket server output:"
    cat "$temp_output"

    # cleanup after each iteration
    cleanup

    echo "============================================================================"
done

# remove the trap at the end of the script
trap - EXIT
