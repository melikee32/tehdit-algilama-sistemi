# Test Ortamı (Issue #7)

İzole bir saldırı/tespit lab'ı: `target` (SSH servisi çalışan zafiyetli kutu), `collector`
(target'ın ağ arayüzünü paylaşan sniffer + log okuyucu sidecar'ı) ve `attacker`
(nmap/hydra/scapy araçları — Faz 7'deki simülasyon script'leri burada çalışacak).

`collector` servisi `network_mode: "service:target"` ile target'ın network namespace'ini
paylaşır, bu yüzden target'a gelen/giden tüm trafiği doğrudan görebilir (Docker bridge'te
üçüncü bir container'dan diğer ikisinin trafiğini görmek mümkün olmadığı için bu yaklaşım
seçildi). Aynı sidecar, target'ın `/var/log` dizinini salt-okunur mount eder — böylece
hem paket yakalama (#5) hem log izleme (#6) aynı ortamdan beslenebilir.

## Kurulum

```bash
cd collector/testenv
docker compose build
docker compose up -d
docker compose ps
```

## Doğrulama

1. **SSH servisi ayakta mı:**
   ```bash
   docker compose exec attacker ssh -o StrictHostKeyChecking=no testuser@target echo ok
   # parola: 123456
   ```
2. **Collector, scapy ile paket yakalayabiliyor mu (target'ın arayüzünde):**
   ```bash
   docker compose exec collector python3 -c "from scapy.all import get_if_list; print(get_if_list())"
   ```
3. **Collector, target'ın auth.log'una erişebiliyor mu:**
   ```bash
   docker compose exec collector sh -c "test -f /var/log/target/auth.log && echo auth.log erisilebilir"
   ```
4. **Attacker, target'ı görebiliyor mu (port tarama ön testi):**
   ```bash
   docker compose exec attacker nmap -p 22,8080 target
   ```
5. **Saldırı simülasyonları (Issue #8) çalışıyor mu:**
   ```bash
   docker compose exec attacker python3 port_scan.py --target target --ports 1-100
   docker compose exec attacker python3 brute_force.py --target target --user testuser
   docker compose exec attacker python3 syn_flood.py --target target --port 22 --count 200
   ```
6. **Collector, üretilen olayları shared/schema formatına uygun yazıyor mu (Issue #9):**
   ```bash
   docker compose exec collector python3 writer/run_collector.py --iface eth0 \
     --log-path /var/log/target/auth.log --dst-ip <target'in labnet IP'si>
   # baska bir terminalde, saldiri simulasyonlarindan biri calisirken:
   docker compose exec collector tail -f output/events.jsonl
   ```

## Kapatma

```bash
docker compose down -v
```

## Notlar

- `testuser:123456` kasıtlı zayıf bir kimlik bilgisidir — sadece bu izole lab içinde
  brute-force simülasyonu (Faz 7 / Issue #8) üretmek için var, gerçek bir ortamda
  kullanılmamalıdır.
- Repo kökü `collector` servisine `/app` altında bind-mount edilir (`/app/collector` +
  `/app/shared`, geliştirme kolaylığı için) — kod değişikliklerinde image'ı yeniden build
  etmeye gerek yok, `docker compose restart collector` yeterli. `writer/run_collector.py`
  (Issue #9) ürettiği `.jsonl` event çıktıları `collector/output/` altında buradan izlenebilir.
