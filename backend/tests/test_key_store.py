import base64


def test_key_store_master_key_format():
    from app.services.key_store import key_store
    key = key_store._get_master_key()
    assert len(key) == 32
