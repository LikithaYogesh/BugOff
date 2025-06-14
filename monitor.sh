#!/bin/bash

# Start enhanced monitoring
echo "[$(date '+%H:%M:%S')] [system]: Monitoring started"

# Start auditd logging in background
tail -f /var/log/audit/audit.log | while read line; do
    echo "[$(date '+%H:%M:%S')] [audit]: $line"
done &

# Monitor file operations
inotifywait -m -r / --format '%T [file]: %w%f %e' --timefmt '%H:%M:%S' &

# Monitor network connections
tcpdump -i any -l -n -w /tmp/network.pcap >/dev/null 2>&1 &

# Monitor system calls
strace -f -e trace=process,network,file -o /tmp/strace.log -p 1 &

# Execute the target file if specified
if [ -n "$FILE_TO_ANALYZE" ] && [ -f "/sandbox/$FILE_TO_ANALYZE" ]; then
    echo "[$(date '+%H:%M:%S')] [exec]: Starting execution of $FILE_TO_ANALYZE"
    /sandbox/$FILE_TO_ANALYZE >/tmp/execution.log 2>&1 &
    EXEC_PID=$!
    
    # Monitor the process
    while kill -0 $EXEC_PID 2>/dev/null; do
        sleep 1
    done
    
    echo "[$(date '+%H:%M:%S')] [exec]: Process exited with status $?"
fi

# Keep container alive for monitoring
tail -f /dev/null