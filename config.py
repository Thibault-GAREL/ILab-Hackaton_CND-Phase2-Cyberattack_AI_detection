# =============================================================================
# API DE SCORING — a remplir le jour J
# =============================================================================
SCORING_API_URL     = "https://TO_FILL"
SCORING_API_KEY     = ""                  # laisser vide si pas de cle
SCORING_API_HEADERS = {
    "Content-Type": "application/json",
    # "X-Api-Key": SCORING_API_KEY,
    # "Authorization": f"Bearer {SCORING_API_KEY}",
}

# =============================================================================
# DATASET LOCAL
# =============================================================================
PARQUET_PATH       = "Dataset_log/logs-raw-merged.parquet"
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
OPENSEARCH_HOST             = "https://TO_FILL.eu-west-3.es.amazonaws.com"
OPENSEARCH_INDEX            = "logs-raw"
OPENSEARCH_REGION           = "eu-west-3"
OPENSEARCH_POLL_INTERVAL_S  = 300   # toutes les 5 minutes
OPENSEARCH_PAGE_SIZE        = 500   # logs par page (scroll)
OPENSEARCH_STATE_FILE       = ".opensearch_state.json"  # sauvegarde du dernier timestamp

# =============================================================================
# BEDROCK — analyse LLM (enrichissement des detections)
# =============================================================================
BEDROCK_ENABLED      = True
BEDROCK_MODEL_ID     = "anthropic.claude-opus-4-6-v1"
BEDROCK_REGION       = "eu-west-3"
BEDROCK_MAX_TOKENS   = 1024
BEDROCK_SAMPLE_LOGS  = 10   # nb de logs a inclure dans le prompt pour contexte

# =============================================================================
# DETECTEURS SPECIFIQUES DS1 — 5 challenges cibles
# =============================================================================

# --- SSH Brute force (auth_method=ssh, status=failure) ---
SSH_BRUTE_FORCE_MIN_FAILURES  = 20
SSH_BRUTE_FORCE_EXTERNAL_ONLY = True

# --- SQL Injection (uri contient des payloads SQL) ---
SQL_INJECTION_MIN_REQUESTS     = 5

# --- Directory Traversal (uri contient ../) ---
DIRECTORY_TRAVERSAL_MIN_ATTEMPTS = 3

# --- SSRF (uri contient une IP interne ou 169.254.169.254) ---
SSRF_MIN_REQUESTS              = 3

# --- Regroupement de campagnes multi-IPs ---
# Deux IPs dont les fenetres d'attaque se chevauchent a +/- N minutes
# sont considerees comme faisant partie de la meme campagne.
CAMPAIGN_OVERLAP_MINUTES       = 90
