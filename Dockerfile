FROM ubuntu:latest

# Install enhanced monitoring tools
RUN apt-get update && apt-get install -y \
    procps \
    lsof \
    net-tools \
    tcpdump \
    strace \
    sysstat \
    inotify-tools \
    bash \
    curl \
    wget \
    auditd && \
    rm -rf /var/lib/apt/lists/*

# Configure auditd for better monitoring
RUN echo "-a exit,always -F arch=b64 -S execve -k process_exec" > /etc/audit/rules.d/process.rules && \
    echo "-a exit,always -F arch=b32 -S execve -k process_exec" >> /etc/audit/rules.d/process.rules && \
    service auditd restart

# Add enhanced monitoring script
COPY monitor.sh /monitor.sh
RUN chmod +x /monitor.sh

# Create sandbox directory
RUN mkdir /sandbox
WORKDIR /sandbox

CMD ["/bin/bash", "/monitor.sh"]