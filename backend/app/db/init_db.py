from app.db.database import Base, engine
from app.db.models import DecryptionSession, Document, ProvenanceRecord, User


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


if __name__ == "__main__":
    init_db()
