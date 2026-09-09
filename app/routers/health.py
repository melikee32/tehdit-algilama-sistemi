from fastapi import APIRouter
from ..schemas import HealthOut

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthOut)
def health_check():
    """Servisin ayakta olup olmadığını kontrol eder (deploy/monitoring için)."""
    return HealthOut(status="ok", service="tehdit-algilama-backend", version="0.1.0")
