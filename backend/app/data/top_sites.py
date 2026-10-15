from pathlib import Path

TOP_SITES_FILE = Path(__file__).with_name("top_sites.txt")
COMMENT_PREFIX = "#"


def load_top_sites() -> list[str]:
    """Registrable domains, most popular first."""
    lines = TOP_SITES_FILE.read_text(encoding="ascii").splitlines()
    return [line for line in lines if line and not line.startswith(COMMENT_PREFIX)]
