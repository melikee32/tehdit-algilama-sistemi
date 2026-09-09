FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap hydra python3 python3-pip iputils-ping openssh-client && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages scapy paramiko

WORKDIR /simulate
CMD ["sleep", "infinity"]
