from app.services.hashing import hashing_service


def test_hash_is_deterministic():
    assert (
        hashing_service.sha256_bytes(b"abc")
        == hashing_service.sha256_bytes(b"abc")
    )
