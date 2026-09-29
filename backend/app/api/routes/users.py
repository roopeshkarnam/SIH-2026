from base64 import b64decode
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models import User
from app.services.key_store import key_store
from app.services.pqc import pqc_service

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/recipients")
def list_recipients(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Users who can receive documents (have an ML-KEM public key)."""
    users = (
        db.query(User)
        .filter(User.kem_public_key.isnot(None), User.is_active.is_(True))
        .order_by(User.username)
        .all()
    )
    return [{"id": u.id, "username": u.username} for u in users]


@router.post("/{user_id}/pqc-keys")
def generate_user_pqc_keys(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.id != user_id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized.")

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    kem = pqc_service.generate_kem_keypair()
    sig = pqc_service.generate_signature_keypair()

    key_store.save_private_key(
        f"{user_id}_kem",
        b64decode(kem["private_key"]),
        kem["algorithm"],
        public_key=b64decode(kem["public_key"]),
    )
    key_store.save_private_key(
        f"{user_id}_sig",
        b64decode(sig["private_key"]),
        sig["algorithm"],
        public_key=b64decode(sig["public_key"]),
    )

    user.kem_public_key = kem["public_key"]
    user.sig_public_key = sig["public_key"]
    db.commit()

    return {
        "user_id": user_id,
        "kem_algorithm": kem["algorithm"],
        "signature_algorithm": sig["algorithm"],
        "kem_public_key": kem["public_key"],
        "signature_public_key": sig["public_key"],
    }
