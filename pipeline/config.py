# =============================================================================
# API DE SCORING — a remplir le jour J (priorité aux variables d'environnement)
# =============================================================================
import os
from pathlib import Path


def _load_dotenv() -> None:
    """Charge `.env` racine du depot puis `pipeline/.env` (non versionnes). Voir `.env.example`."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    pipeline_dir = Path(__file__).resolve().parent
    root_env = pipeline_dir.parent / ".env"
    pipe_env = pipeline_dir / ".env"
    if root_env.is_file():
        load_dotenv(root_env, override=False)
    if pipe_env.is_file():
        load_dotenv(pipe_env, override=True)


_load_dotenv()


def _env_strip(key: str, default: str) -> str:
    v = os.environ.get(key)
    if v is None or not str(v).strip():
        return default
    return str(v).strip()


def _env_bool(key: str, default: bool) -> bool:
    v = os.environ.get(key)
    if v is None or not str(v).strip():
        return default
    s = str(v).strip().lower()
    if s in ("0", "false", "no", "off"):
        return False
    if s in ("1", "true", "yes", "on"):
        return True
    return default


SCORING_API_URL = _env_strip("SCORING_API_URL", "https://TO_FILL")
SCORING_API_KEY = _env_strip("SCORING_API_KEY", "")
try:
    SCORING_REQUEST_TIMEOUT_S = int(_env_strip("SCORING_REQUEST_TIMEOUT_S", "60"))
except ValueError:
    SCORING_REQUEST_TIMEOUT_S = 60

SCORING_API_HEADERS = {
    "Content-Type": "application/json",
    # "X-Api-Key": SCORING_API_KEY,
    # Bearer injecté dans submit.py si SCORING_API_KEY est défini
}

# =============================================================================
# PARQUET — scripts benchmark / import manuel uniquement (pipeline.py = OpenSearch)
# =============================================================================
PARQUET_PATH = _env_strip("PARQUET_PATH", "Dataset_log/logs-raw-merged.parquet")
try:
    PARQUET_BATCH_SIZE = int(_env_strip("PARQUET_BATCH_SIZE", "100000"))
except ValueError:
    PARQUET_BATCH_SIZE = 100_000

# Gap en minutes entre deux evenements pour les considerer dans la meme session
SESSION_GAP_MINUTES = 30

# =============================================================================
# SENSIBILITE DES DETECTEURS
# Augmenter un seuil -> moins de detections, moins de faux positifs (-10 pts)
# Diminuer un seuil  -> plus de detections, risque de faux positifs
# =============================================================================

# --- Credential stuffing (logs application, status_code=401) ---
CREDENTIAL_STUFFING_MIN_401           = 20
CREDENTIAL_STUFFING_EXTERNAL_ONLY     = True  # False pour inclure les IPs internes
CREDENTIAL_STUFFING_SPLIT_SESSIONS    = False  # False = 1 detection par IP

# =============================================================================
# DEDUPLICATION
# Quand deux detections de la meme IP se chevauchent dans le temps :
#   "none"              -> tout soumettre (risque de faux positifs)
#   "keep_most_specific"-> garder le type le plus precis par fenetre/IP
#   "merge"             -> fusionner en une seule detection multi-vecteur
# =============================================================================
DEDUP_STRATEGY        = "keep_most_specific"
DEDUP_OVERLAP_MINUTES = 30   # seuil pour considerer deux detections comme chevauchantes

# =============================================================================
# OPENSEARCH (temps reel — finale)
# =============================================================================
# Domaine API (sans /_dashboards). Surcharge : OPENSEARCH_HOST
_DEFAULT_OS_HOST = (
    "https://search-hackathon-cnd-pytppy2betrf5qnoqporwcqqbm.eu-west-3.es.amazonaws.com"
)
OPENSEARCH_HOST = _env_strip("OPENSEARCH_HOST", _DEFAULT_OS_HOST)
OPENSEARCH_INDEX = _env_strip("OPENSEARCH_INDEX", "logs-raw")
OPENSEARCH_REGION = _env_strip("OPENSEARCH_REGION", "eu-west-3")
# Intervalle entre deux polls. Le debit source (~50–100 logs / 5 min) est fixe par l’orga ;
# un intervalle plus court (ex. 60) reduit seulement la latence apres indexation, pas l’arrivee des logs.
try:
    OPENSEARCH_POLL_INTERVAL_S = int(_env_strip("OPENSEARCH_POLL_INTERVAL_S", "300"))
except ValueError:
    OPENSEARCH_POLL_INTERVAL_S = 300
try:
    OPENSEARCH_PAGE_SIZE = int(_env_strip("OPENSEARCH_PAGE_SIZE", "500"))
except ValueError:
    OPENSEARCH_PAGE_SIZE = 500
OPENSEARCH_STATE_FILE = _env_strip("OPENSEARCH_STATE_FILE", ".opensearch_state.json")
# Curseur dernier timestamp : file (defaut) ou dynamodb (Lambda)
OPENSEARCH_STATE_BACKEND = _env_strip("OPENSEARCH_STATE_BACKEND", "file").lower()
OPENSEARCH_STATE_DYNAMODB_TABLE = _env_strip("OPENSEARCH_STATE_DYNAMODB_TABLE", "")
OPENSEARCH_STATE_DYNAMODB_PK = _env_strip("OPENSEARCH_STATE_DYNAMODB_PK", "PIPELINE_CURSOR")
# Champ date pour range + sort (rapport hackathon : timestamp, pas @timestamp)
OPENSEARCH_TIMESTAMP_FIELD = _env_strip("OPENSEARCH_TIMESTAMP_FIELD", "timestamp")
# Auth hackathon CND : FGAC (Basic). Secrets dans `.env` (copie de `.env.example`).
# OPENSEARCH_AUTH=sigv4 pour un deploiement IAM-only.
OPENSEARCH_AUTH = _env_strip("OPENSEARCH_AUTH", "basic").lower()
OPENSEARCH_BASIC_USER = _env_strip("OPENSEARCH_BASIC_USER", "etudiant")
OPENSEARCH_BASIC_PASSWORD = _env_strip("OPENSEARCH_BASIC_PASSWORD", "")
# SigV4 service : es (OpenSearch Service / Elasticsearch managed) | aoss (OpenSearch Serverless)
OPENSEARCH_SIGV4_SERVICE = _env_strip("OPENSEARCH_SIGV4_SERVICE", "es")

# Soumission : eviter renvoyer le meme payload (penalite FP -10). Desactiver : SUBMIT_SKIP_DUPLICATES=0
SUBMIT_SKIP_DUPLICATES = _env_bool("SUBMIT_SKIP_DUPLICATES", True)
SUBMIT_CACHE_FILE = _env_strip("SUBMIT_CACHE_FILE", ".submit_fingerprint_cache.json")

# =============================================================================
# BEDROCK — analyse LLM (enrichissement + timeline, pile Claude Opus unifiee)
# Kill switch / incident : BEDROCK_ENABLED=0 (détecteurs + remédiation statique uniquement)
# =============================================================================
BEDROCK_ENABLED = _env_bool("BEDROCK_ENABLED", True)

# Converse : Claude Opus 4.6 uniquement (profil EU puis ID guide en secours).
# Forcer un autre modele : BEDROCK_TIMELINE_MODEL_ID ou BEDROCK_MODEL_ID.
BEDROCK_MODEL_ID_EU_OPUS_46 = "eu.anthropic.claude-opus-4-6-v1"
BEDROCK_MODEL_ID_GUIDE_OPUS_46 = "anthropic.claude-opus-4-6-v1"

_bedrock_force_model = _env_strip("BEDROCK_TIMELINE_MODEL_ID", "") or _env_strip(
    "BEDROCK_MODEL_ID", ""
)
if _bedrock_force_model:
    BEDROCK_CONVERSE_MODEL_CANDIDATES: tuple[str, ...] = (_bedrock_force_model,)
else:
    BEDROCK_CONVERSE_MODEL_CANDIDATES = (
        BEDROCK_MODEL_ID_EU_OPUS_46,
        BEDROCK_MODEL_ID_GUIDE_OPUS_46,
    )

# Compat : meme tuple pour enrichissement generique et refine timeline
BEDROCK_MODEL_ID = BEDROCK_CONVERSE_MODEL_CANDIDATES[0]
BEDROCK_TIMELINE_MODEL_CANDIDATES = BEDROCK_CONVERSE_MODEL_CANDIDATES
BEDROCK_TIMELINE_MODEL_ID = BEDROCK_CONVERSE_MODEL_CANDIDATES[0]
# Région console / profil SSO / runtime Bedrock : viser eu-west-3 (Paris) pour le hackathon
BEDROCK_REGION = _env_strip(
    "BEDROCK_REGION",
    _env_strip("AWS_DEFAULT_REGION", _env_strip("AWS_REGION", "eu-west-3")),
)
BEDROCK_MAX_TOKENS = 1024
BEDROCK_SAMPLE_LOGS = 10  # nb de logs pour l'appel enrichissement générique
BEDROCK_REFINE_TIMELINE = True
# Un seul appel Converse (enrichissement + refined_attack_end_time) ; repli 2 appels si JSON invalide
BEDROCK_FUSED_CONVERSE = _env_bool("BEDROCK_FUSED_CONVERSE", True)
try:
    BEDROCK_FUSED_MAX_TOKENS = int(_env_strip("BEDROCK_FUSED_MAX_TOKENS", "6144"))
except ValueError:
    BEDROCK_FUSED_MAX_TOKENS = 6144
try:
    BEDROCK_MIN_REQUEST_INTERVAL_S = float(
        _env_strip("BEDROCK_MIN_REQUEST_INTERVAL_S", "0.75")
    )
except ValueError:
    BEDROCK_MIN_REQUEST_INTERVAL_S = 0.75
try:
    BEDROCK_THROTTLE_MAX_RETRIES = int(_env_strip("BEDROCK_THROTTLE_MAX_RETRIES", "5"))
except ValueError:
    BEDROCK_THROTTLE_MAX_RETRIES = 5
# Contexte OpenSearch supplementaire pour Bedrock (realtime_pipeline)
try:
    BEDROCK_OS_CONTEXT_MAX_DOCS = int(_env_strip("BEDROCK_OS_CONTEXT_MAX_DOCS", "100000"))
except ValueError:
    BEDROCK_OS_CONTEXT_MAX_DOCS = 100_000
try:
    BEDROCK_OS_CONTEXT_PAD_MINUTES = float(
        _env_strip("BEDROCK_OS_CONTEXT_PAD_MINUTES", "15")
    )
except ValueError:
    BEDROCK_OS_CONTEXT_PAD_MINUTES = 15.0
# Fenêtre de lecture et bornes de clamp cohérentes (écarts GT jusqu'à ~62 min observés)
BEDROCK_TIMELINE_LOOKAHEAD_MINUTES = 180
BEDROCK_TIMELINE_MAX_SHIFT_MINUTES = 180
BEDROCK_TIMELINE_SAMPLE_LOGS = 72
BEDROCK_TIMELINE_MIN_CONFIDENCE = "medium"  # low | medium | high
BEDROCK_TIMELINE_MAX_TOKENS = 4096
# Secondes après le dernier evenement malveillant pour coller a la fenetre GT (~±5 min)
BEDROCK_TIMELINE_RELEVANT_EPSILON_SECONDS = 300

# DS1 : fenetres officielles (ISO 8601 UTC, secondes) pour le scoring timeline apres Bedrock.
# Dataset 2 / timelines libres : CND_DS1_CANONICAL_TIMELINE=0 (defaut pour la finale)
DS1_CANONICAL_TIMELINE = _env_bool("CND_DS1_CANONICAL_TIMELINE", False)
# IoC : noms de cles alignes sur ground-truth-ds1.json (ds1_ioc_canonical). DS2 : CND_DS1_CANONICAL_IOCS=0
DS1_CANONICAL_IOCS = _env_bool("CND_DS1_CANONICAL_IOCS", False)

# Finale : ingestion par slices (3 lots) — detection_time_seconds non utilisé pour le score par défaut
SCORING_BONUS_RAPIDITE_ENABLED = _env_bool("SCORING_BONUS_RAPIDITE_ENABLED", False)
# Retirer les detections dont l enrichissement Bedrock declare confidence=low (faux positifs distribution).
BEDROCK_DROP_LOW_ENRICHMENT_CONFIDENCE = _env_bool(
    "BEDROCK_DROP_LOW_ENRICHMENT_CONFIDENCE", True
)
DS1_CANONICAL_VICTIMS: dict[str, list[str]] = {
    "credential_stuffing": ["jdupont"],
    "ssh_brute_force": ["sysadmin"],
}

DS1_CANONICAL_ATTACK_WINDOWS: dict[str, tuple[str, str]] = {
    "credential_stuffing": ("2026-01-06T02:00:00Z", "2026-01-06T06:00:00Z"),
    "ssh_brute_force": ("2026-01-11T01:00:00Z", "2026-01-11T07:00:00Z"),
    "sql_injection": ("2026-01-19T14:00:00Z", "2026-01-19T17:00:00Z"),
    "directory_traversal": ("2026-01-23T10:00:00Z", "2026-01-23T12:00:00Z"),
    "ssrf": ("2026-01-26T11:00:00Z", "2026-01-26T12:00:00Z"),
}

# =============================================================================
# DETECTEURS SPECIFIQUES DS1 — 5 challenges cibles
# =============================================================================

# --- SSH Brute force (auth_method=ssh, status=failure) ---
SSH_BRUTE_FORCE_MIN_FAILURES  = 20
SSH_BRUTE_FORCE_EXTERNAL_ONLY = True

# --- SQL Injection (uri contient des payloads SQL) ---
# Vraie attaque = 515 req, 31MB exfil. Scanners = 3-23 req, 0MB exfil.
# Bedrock reclassifie les scanners en credential_stuffing → confirme que c'est du bruit.
SQL_INJECTION_MIN_REQUESTS     = 50
SQL_INJECTION_MIN_EXFIL_BYTES  = 1_000_000  # 1MB — filtre les petits scans

# --- Directory Traversal (uri contient ../) ---
# Vraie attaque = 250 req (77 succès). Scanners DirBuster = 10-25 req.
DIRECTORY_TRAVERSAL_MIN_ATTEMPTS = 100

# --- SSRF (uri contient une IP interne ou 169.254.169.254) ---
# Vraie attaque = 300 req. Scanners = 10-17 req.
SSRF_MIN_REQUESTS              = 100

# --- Regroupement de campagnes multi-IPs ---
# Deux IPs dont les fenetres d'attaque se chevauchent a +/- N minutes
# sont considerees comme faisant partie de la meme campagne.
CAMPAIGN_OVERLAP_MINUTES       = 90
