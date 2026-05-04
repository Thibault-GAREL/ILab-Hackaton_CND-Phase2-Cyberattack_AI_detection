"""Schemas Pydantic pour les detections."""

from typing import Literal, Optional

from pydantic import BaseModel, Field, model_validator


MAX_LINES_OPENSEARCH = 500_000
MAX_LINES_PARQUET = 2_000_000
DEFAULT_TIMEOUT_S = 600
MAX_TIMEOUT_S = 7200


class PipelineRunRequest(BaseModel):
    """
    Lancement d'une analyse : OpenSearch (delta + curseur) ou Parquet (bench local).

    - max_lines : pour OpenSearch, limite le nombre de documents lus (équivalent --max-docs) ;
      pour Parquet, limite le nombre de lignes lues depuis le fichier.
    """

    source: Literal["opensearch", "parquet"] = "opensearch"
    max_lines: Optional[int] = Field(
        default=None,
        description="Plafond de lignes/logs ; None = illimité (OpenSearch) ou lecture complète (Parquet).",
    )
    # OpenSearch-only (ignorés si source=parquet)
    accumulate: Optional[bool] = None
    reset_state: Optional[bool] = None
    dry_run_state: Optional[bool] = None
    no_dedup: Optional[bool] = None
    submit: Optional[bool] = None
    submit_dry_run: Optional[bool] = None
    # Parquet-only
    parquet_path: Optional[str] = Field(
        default=None,
        description="Chemin relatif à la racine du dépôt ou absolu sous la racine du dépôt.",
    )
    parquet_batch_rows: int = Field(
        default=400_000,
        ge=1_000,
        le=2_000_000,
        description="Taille de lot PyArrow pour la lecture Parquet.",
    )
    # Environnement pipeline
    bedrock_enabled: Optional[bool] = None
    model_id: Optional[str] = None
    timeout_seconds: Optional[int] = Field(
        default=None,
        ge=30,
        le=MAX_TIMEOUT_S,
        description="Timeout subprocess (défaut 600 s OpenSearch, 3600 s Parquet si non fourni).",
    )

    @model_validator(mode="after")
    def _limits_and_submit(self) -> "PipelineRunRequest":
        if self.max_lines is not None:
            cap = MAX_LINES_OPENSEARCH if self.source == "opensearch" else MAX_LINES_PARQUET
            if self.max_lines > cap:
                raise ValueError(f"max_lines ne peut pas dépasser {cap} pour source={self.source}")
        if self.submit and self.submit_dry_run:
            raise ValueError("submit et submit_dry_run sont mutuellement exclusifs")
        return self


class PipelineRunResponse(BaseModel):
    status: str
    detections_count: int
    message: str
    source: str = "opensearch"
    stdout_tail: str = ""
    stderr_tail: str = ""


class DetectionSummary(BaseModel):
    id: int
    challenge_id: str
    attack_type: str
    attacker_ips: list[str]
    victim_accounts: list[str]
    start_time: str
    end_time: str
    severity: str
    detection_time_seconds: int
    indicators: dict
    remediation: dict | None = None


class DetectionsResponse(BaseModel):
    total: int
    detections: list[DetectionSummary]


class DetectionStats(BaseModel):
    total_detections: int
    by_attack_type: dict[str, int]
    by_severity: dict[str, int]
    unique_attacker_ips: int
    all_under_300s: bool


class TimelineEntry(BaseModel):
    challenge_id: str
    attack_type: str
    start_time: str
    end_time: str
    severity: str
    attacker_ips: list[str]
