# Build context repo kokudur (bkz. testenv/docker-compose.yml) -- collector,
# writer/event_writer.py uzerinden shared/schema'yi (Issue #28) import eder,
# bu yuzden image icinde collector ile shared kardes klasorler olarak durur.
FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends tcpdump iproute2 iputils-ping && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app/collector
COPY collector/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY collector/ .
COPY shared/ /app/shared

CMD ["sleep", "infinity"]
