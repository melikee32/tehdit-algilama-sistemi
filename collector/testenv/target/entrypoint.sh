#!/bin/sh
set -e

# auth.log/syslog uretimi icin rsyslog daemon
rsyslogd

# port tarama testleri icin ek acik bir servis (8080)
python3 -m http.server 8080 --directory /tmp >/dev/null 2>&1 &

# sshd'yi foreground'da calistir, container bu process ile ayakta kalir
exec /usr/sbin/sshd -D
