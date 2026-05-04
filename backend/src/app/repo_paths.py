"""Résolution de la racine du dépôt (dossier contenant pipeline/)."""

from pathlib import Path


def find_repo_root() -> Path:
    """
    Racine du repo : parent commun à backend/ et pipeline/.
    Local : …/backend/src/app/repo_paths.py → remonte jusqu'à trouver pipeline/.
    Docker : /app/src/app/repo_paths.py → /app contient pipeline/.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        pl = parent / "pipeline"
        if pl.is_dir() and (pl / "__init__.py").is_file():
            return parent
    raise RuntimeError(f"Racine du depot introuvable (pipeline/) depuis {here}")
