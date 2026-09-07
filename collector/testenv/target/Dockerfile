FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-server rsyslog python3 && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /run/sshd

# Brute-force simulasyonu icin kasitli zayif parolali test kullanicisi
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:123456" | chpasswd

RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    printf '\nSyslogFacility AUTH\nLogLevel VERBOSE\n' >> /etc/ssh/sshd_config

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 22: SSH (brute-force hedefi), 8080: ek acik port (port tarama gerceklik testi icin)
EXPOSE 22 8080
ENTRYPOINT ["/entrypoint.sh"]
