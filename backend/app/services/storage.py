from pathlib import Path
import shutil

from app.core.config import settings


def initialize_storage():

    root = Path(settings.storage_root)

    (root / "encrypted").mkdir(
        parents=True,
        exist_ok=True,
    )

    (root / "temp").mkdir(
        parents=True,
        exist_ok=True,
    )

    (root / "quarantine").mkdir(
        parents=True,
        exist_ok=True,
    )


def save_uploaded_file(
    source_file,
    destination: Path,
) -> None:

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with destination.open("wb") as output:

        shutil.copyfileobj(
            source_file,
            output,
        )