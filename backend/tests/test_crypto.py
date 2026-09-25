from app.services.encryption import encryption_service


def test_aes_round_trip():
    key = encryption_service.generate_document_key()
    plaintext = b"SIH confidential document"
    encrypted = encryption_service.encrypt_document(plaintext, key)
    recovered = encryption_service.decrypt_document(encrypted, key)
    assert recovered == plaintext
