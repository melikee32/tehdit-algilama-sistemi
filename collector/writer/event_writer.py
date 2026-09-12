"""Collector Ciktilarini shared/schema Formatina Donusturme (Issue #9)
=========================================================================
`capture/sniffer.py` (Issue #5) ve `logs/log_reader.py` (Issue #6)
tarafindan uretilen ham event dict'lerini shared/schema Pydantic
modelleri (Issue #28) ile dogrular ve JSON Lines (.jsonl) formatinda
`collector/output/` altina yazar.

Neden JSON Lines: her satir bagimsiz bir event oldugu icin, dosya
yaziliyorken ayni anda baska bir surec (rules-engine, dashboard) satir
satir okuyabilir (append-only, tail edilebilir).
"""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from typing import Union

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from shared.schema import LoginAttemptEvent, TrafficEvent  # noqa: E402

_MODELS_BY_EVENT_TYPE = {
    "connection_attempt": TrafficEvent,
    "login_attempt": LoginAttemptEvent,
}


class EventWriter:
    """Ham event dict'lerini dogrulayip bir .jsonl dosyasina append eder."""

    def __init__(self, output_path: Union[str, Path]):
        self._output_path = Path(output_path)
        self._output_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, raw_event: dict, event_type: str) -> dict:
        """raw_event'i event_type'a karsilik gelen shared/schema modeline
        gore dogrular, dosyaya JSONL satiri olarak yazar ve yazilan
        (dogrulanmis) dict'i geri dondurur.

        Args:
            raw_event: capture/sniffer.py veya logs/log_reader.py ciktisi.
            event_type: "connection_attempt" | "login_attempt".

        Raises:
            KeyError: event_type bilinmiyorsa.
            pydantic.ValidationError: alanlar semaya uymuyorsa.
        """
        model_cls = _MODELS_BY_EVENT_TYPE.get(event_type)
        if model_cls is None:
            raise KeyError(f"Bilinmeyen event_type: {event_type!r}")

        payload = {**raw_event, "event_type": event_type}
        if event_type == "connection_attempt":
            # Tek bir SYN paketinden el sikismanin tamamlanip
            # tamamlanmadigi (yani baglantinin gercekten kurulup
            # kurulmadigi) anlasilamaz -- sniffer.py sadece baglanti
            # denemesini yakaliyor. Bu yuzden aksi belirtilmedikce
            # guvenli varsayilan olarak False kullaniliyor.
            payload.setdefault("success", False)

        validated = model_cls.model_validate(payload)
        line = validated.model_dump_json()

        with self._lock:
            with open(self._output_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

        return json.loads(line)
