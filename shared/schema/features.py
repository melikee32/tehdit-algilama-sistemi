"""
shared/schema/features.py — Issue #30

ML motorunun girdi olarak alacagi oznitelik matrisi.
Bu model, ag trafiğinden (Scapy/Zeek — Kisi 1) veya
ham event'lerden turetilen sayisal ozelliklerdir.

Kisi 3 (ML motoru), IsolationForest vb. modeline
MLFeatureVector.to_array() ciktisini besler.
"""
from pydantic import BaseModel, Field
from typing import Optional


class MLFeatureVector(BaseModel):
    """
    Tek bir ag akisi (flow) icin oznitelik vektoru.
    CICIDS2017 / NSL-KDD veri setiyle uyumlu temel ozellikler.
    """

    # Kaynak / Hedef Bilgisi
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None          # "tcp", "udp", "icmp"

    # Akis Ozellikleri
    duration_ms: float = Field(0.0, ge=0.0, description="Akim suresi (ms)")
    packet_count: int = Field(0, ge=0, description="Toplam paket sayisi")
    byte_count: int = Field(0, ge=0, description="Toplam byte miktari")
    fwd_packet_count: int = Field(0, ge=0, description="Ileri yonlu paket sayisi")
    bwd_packet_count: int = Field(0, ge=0, description="Geri yonlu paket sayisi")

    # Istatistiksel Ozellikler
    mean_packet_size: float = Field(0.0, ge=0.0)
    std_packet_size: float = Field(0.0, ge=0.0)
    mean_iat_ms: float = Field(0.0, ge=0.0, description="Paketler arasi ort. sure (ms)")
    std_iat_ms: float = Field(0.0, ge=0.0)

    # TCP Bayraklari (diger protokollerde 0 kalir)
    syn_count: int = Field(0, ge=0)
    fin_count: int = Field(0, ge=0)
    rst_count: int = Field(0, ge=0)
    ack_count: int = Field(0, ge=0)

    # Ham payload (ek veri, ML modeline girmez)
    raw_payload: Optional[dict] = None

    def to_array(self) -> list[float]:
        """
        Modele beslenecek sayisal oznitelik dizisi.
        Siralamayi degistirmek modeli bozar, dikkatli olun.
        """
        return [
            self.duration_ms,
            self.packet_count,
            self.byte_count,
            self.fwd_packet_count,
            self.bwd_packet_count,
            self.mean_packet_size,
            self.std_packet_size,
            self.mean_iat_ms,
            self.std_iat_ms,
            self.syn_count,
            self.fin_count,
            self.rst_count,
            self.ack_count,
        ]
