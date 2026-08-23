# Tehdit Algılama Sistemi

Yapay Zeka Destekli Tehdit Algılama ve Zafiyet Yönetimi — Bitirme Projesi (4 kişilik ekip)

Hibrit (kural tabanlı + makine öğrenmesi) korelasyonlu, gerçek zamanlı ağ saldırı tespit sistemi.

## Modüller

| Klasör | Sorumlu | Açıklama |
|---|---|---|
| `collector/` | Kişi 1 | Ağ trafiği/log toplama, test ortamı, saldırı simülasyonları |
| `rules-engine/` | Kişi 2 (ben) | Kural tabanlı tespit (port tarama, brute-force, SYN flood) + zafiyet tarama/CVE eşleştirme |
| `ml-engine/` | Kişi 3 | Anomali tespit modeli (Isolation Forest), değerlendirme |
| `dashboard/` | Kişi 4 | React panel, FastAPI backend, WebSocket, correlation engine |
| `shared/schema/` | Ortak | Modüller arası ortak JSON veri şeması / API sözleşmesi |

## Durum

- [x] Repo kuruldu
- [ ] Ortak JSON şeması netleştirildi
- [ ] MVP: kural tabanlı tespit + temel panel
- [ ] ML modülü eklendi
- [ ] Correlation engine
- [ ] Zafiyet tarama modülü
- [ ] Uçtan uca entegrasyon testi
