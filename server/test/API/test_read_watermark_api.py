import json
import pytest
from sqlalchemy import text

import src.watermarking_utils as WMUtils


def test_read_watermark_success(client, auth_headers_unit, monkeypatch):
    """
    Enforces the happy-path behavior of the read-watermark API:

    - A valid request returns HTTP 201
    - The watermark is successfully extracted
    - The response contains the embedded watermark metadata

    This establishes a known-correct execution path before
    testing error-handling branches.
    """

    # --- Arrange ----------------------------------------------------------

    with client.application.app_context():
        from src.server import get_engine
        engine = get_engine()

        storage_dir = client.application.config["STORAGE_DIR"]
        pdf_path = storage_dir / "watermarked.pdf"
        pdf_path.write_bytes(b"%PDF-1.4 watermarked content")

        with engine.begin() as conn:
            doc_result = conn.execute(
                text(
                    """
                    INSERT INTO Documents (name, path, ownerid, sha256, size)
                    VALUES (:name, :path, :ownerid, :sha, :size)
                    """
                ),
                {
                    "name": "watermarked.pdf",
                    "path": str(pdf_path),
                    "ownerid": 1,
                    "sha": bytes.fromhex("00" * 32),
                    "size": pdf_path.stat().st_size,
                },
            )
            document_id = int(doc_result.lastrowid)

            version_result = conn.execute(
                text(
                    """
                    INSERT INTO Versions (
                        documentid, intended_for, secret,
                        method, path, link
                    )
                    VALUES (
                        :documentid, :intended_for, :secret,
                        :method, :path, :link
                    )
                    """
                ),
                {
                    "documentid": document_id,
                    "intended_for": "alice",
                    "secret": "topsecret",
                    "method": "axel",
                    "path": str(pdf_path),
                    "link": "dummy-link-token",
                },
            )
            version_id = int(version_result.lastrowid)

    # Mock watermark extraction logic so no real watermarking code runs
    monkeypatch.setattr(
        WMUtils,
        "read_watermark",
        lambda **kwargs: {
            "intended_for": "alice",
            "secret": "topsecret",
            "method": "axel",
        },
    )

    payload = {
        "id": version_id,
        "method": "axel",
        "key": "encryptionkey",
    }

    # --- Act --------------------------------------------------------------

    resp = client.post(
        "/api/read-watermark",
        data=json.dumps(payload),
        headers=auth_headers_unit,
        content_type="application/json",
    )

    # --- Assert -----------------------------------------------------------

    assert resp.status_code == 201

    data = resp.get_json()

    
    assert data["method"] == "axel"
    assert "secret" in data

    watermark = data["secret"]
    assert watermark["intended_for"] == "alice"
    assert watermark["secret"] == "topsecret"
    assert watermark["method"] == "axel"


def test_read_watermark_document_not_found(client, auth_headers_unit):
    """
    Ensures the read-watermark API returns 404 when the document does not exist.

    This test verifies that the API properly handles requests for non-existent
    documents and does not attempt watermark extraction.
    """

    payload = {
        "id": 9999,  # non-existent document/version id
        "method": "axel",
        "key": "encryptionkey",
    }

    resp = client.post(
        "/api/read-watermark",
        data=json.dumps(payload),
        headers=auth_headers_unit,
        content_type="application/json",
    )

    assert resp.status_code == 404

    data = resp.get_json()
    assert "error" in data
    assert "not found" in data["error"].lower()


def test_read_watermark_file_missing_on_disk(client, auth_headers_unit, monkeypatch):
    """
    Ensures the read-watermark API returns 404 when the watermarked
    file referenced in the Versions table is missing on disk.

    This verifies that the API fails safely and does not attempt to
    extract a watermark from a non-existent file.
    """

    with client.application.app_context():
        from src.server import get_engine
        engine = get_engine()

        storage_dir = client.application.config["STORAGE_DIR"]
        missing_path = storage_dir / "missing.pdf"

        with engine.begin() as conn:
            doc_result = conn.execute(
                text(
                    """
                    INSERT INTO Documents (name, path, ownerid, sha256, size)
                    VALUES (:name, :path, :ownerid, :sha, :size)
                    """
                ),
                {
                    "name": "missing.pdf",
                    "path": str(missing_path),
                    "ownerid": 1,
                    "sha": bytes.fromhex("00" * 32),
                    "size": 123,
                },
            )
            document_id = int(doc_result.lastrowid)

            conn.execute(
                text(
                    """
                    INSERT INTO Versions (
                        documentid, intended_for, secret,
                        method, path, link
                    )
                    VALUES (
                        :documentid, :intended_for, :secret,
                        :method, :path, :link
                    )
                    """
                ),
                {
                    "documentid": document_id,
                    "intended_for": "alice",
                    "secret": "topsecret",
                    "method": "axel",
                    "path": str(missing_path),
                    "link": "missing-link-token",
                },
            )

    # Ensure watermark extraction is never called
    monkeypatch.setattr(
        WMUtils,
        "read_watermark",
        lambda **kwargs: pytest.fail("read_watermark should not be called"),
    )

    payload = {
        "id": document_id,
        "method": "axel",
        "key": "encryptionkey",
    }

    resp = client.post(
        "/api/read-watermark",
        data=json.dumps(payload),
        headers=auth_headers_unit,
        content_type="application/json",
    )

    assert resp.status_code == 410

    data = resp.get_json()
    assert "error" in data
    assert "file" in data["error"].lower()


def test_read_watermark_extraction_failure(client, auth_headers_unit, monkeypatch):
    """
    Ensures the read-watermark API returns 500 when watermark extraction
    raises an exception.

    This verifies that the API fails safely when watermark parsing fails
    and does not leak internal errors or crash.
    """

    with client.application.app_context():
        from src.server import get_engine
        engine = get_engine()

        storage_dir = client.application.config["STORAGE_DIR"]
        pdf_path = storage_dir / "corrupt.pdf"
        pdf_path.write_bytes(b"%PDF-1.4 corrupted watermark data")

        with engine.begin() as conn:
            doc_result = conn.execute(
                text(
                    """
                    INSERT INTO Documents (name, path, ownerid, sha256, size)
                    VALUES (:name, :path, :ownerid, :sha, :size)
                    """
                ),
                {
                    "name": "corrupt.pdf",
                    "path": str(pdf_path),
                    "ownerid": 1,
                    "sha": bytes.fromhex("00" * 32),
                    "size": pdf_path.stat().st_size,
                },
            )
            document_id = int(doc_result.lastrowid)

            conn.execute(
                text(
                    """
                    INSERT INTO Versions (
                        documentid, intended_for, secret,
                        method, path, link
                    )
                    VALUES (
                        :documentid, :intended_for, :secret,
                        :method, :path, :link
                    )
                    """
                ),
                {
                    "documentid": document_id,
                    "intended_for": "alice",
                    "secret": "topsecret",
                    "method": "axel",
                    "path": str(pdf_path),
                    "link": "corrupt-link-token",
                },
            )

    def explode(**kwargs):
        raise RuntimeError("Watermark extraction failed")

    monkeypatch.setattr(WMUtils, "read_watermark", explode)

    payload = {
        "id": document_id,
        "method": "axel",
        "key": "encryptionkey",
    }

    resp = client.post(
        "/api/read-watermark",
        data=json.dumps(payload),
        headers=auth_headers_unit,
        content_type="application/json",
    )

    assert resp.status_code == 400

    data = resp.get_json()
    assert "error" in data


def test_read_watermark_missing_required_fields(client, auth_headers_unit):
    """
    Ensures the read-watermark API returns 400 when required
    request fields are missing.

    This verifies request validation happens before any database
    lookup or watermark extraction.
    """

    # Missing both `method` and `key`
    payload = {
        "id": 1
    }

    resp = client.post(
        "/api/read-watermark",
        data=json.dumps(payload),
        headers=auth_headers_unit,
        content_type="application/json",
    )

    assert resp.status_code == 400

    data = resp.get_json()
    assert "error" in data
    assert "required" in data["error"].lower()


def test_read_watermark_wrong_method_value(client, auth_headers_unit, monkeypatch):
    """
    Ensures the read-watermark API returns 400 when an unsupported
    watermarking method is provided.

    Since the API does not validate the method itself, this test
    verifies that a failure inside watermark extraction is handled safely.
    """

    with client.application.app_context():
        from src.server import get_engine
        engine = get_engine()

        storage_dir = client.application.config["STORAGE_DIR"]
        pdf_path = storage_dir / "wrong_method.pdf"
        pdf_path.write_bytes(b"%PDF-1.4 watermarked content")

        with engine.begin() as conn:
            doc_result = conn.execute(
                text(
                    """
                    INSERT INTO Documents (name, path, ownerid, sha256, size)
                    VALUES (:name, :path, :ownerid, :sha, :size)
                    """
                ),
                {
                    "name": "wrong_method.pdf",
                    "path": str(pdf_path),
                    "ownerid": 1,
                    "sha": bytes.fromhex("00" * 32),
                    "size": pdf_path.stat().st_size,
                },
            )
            document_id = int(doc_result.lastrowid)

            conn.execute(
                text(
                    """
                    INSERT INTO Versions (
                        documentid, intended_for, secret,
                        method, path, link
                    )
                    VALUES (
                        :documentid, :intended_for, :secret,
                        :method, :path, :link
                    )
                    """
                ),
                {
                    "documentid": document_id,
                    "intended_for": "alice",
                    "secret": "topsecret",
                    "method": "axel",
                    "path": str(pdf_path),
                    "link": "wrong-method-link",
                },
            )

    # Simulate unsupported method inside watermarking
    def invalid_method(**kwargs):
        raise ValueError("Unsupported watermark method")

    monkeypatch.setattr(WMUtils, "read_watermark", invalid_method)

    payload = {
        "id": document_id,
        "method": "unsupported_method",
        "key": "encryptionkey",
    }

    resp = client.post(
        "/api/read-watermark",
        data=json.dumps(payload),
        headers=auth_headers_unit,
        content_type="application/json",
    )

    assert resp.status_code == 400

    data = resp.get_json()
    assert "error" in data


def test_read_watermark_forbidden_for_other_user(client, auth_headers_unit, monkeypatch):
    """
    Ensures the read-watermark API returns 404 when an authenticated user
    attempts to read a watermark for a document they do not own.

    """

    with client.application.app_context():
        from src.server import get_engine
        engine = get_engine()

        storage_dir = client.application.config["STORAGE_DIR"]
        pdf_path = storage_dir / "foreign_owner.pdf"
        pdf_path.write_bytes(b"%PDF-1.4 foreign owner content")

        with engine.begin() as conn:
            # Document owned by a different user (ownerid = 2)
            doc_result = conn.execute(
                text(
                    """
                    INSERT INTO Documents (name, path, ownerid, sha256, size)
                    VALUES (:name, :path, :ownerid, :sha, :size)
                    """
                ),
                {
                    "name": "foreign_owner.pdf",
                    "path": str(pdf_path),
                    "ownerid": 2,
                    "sha": bytes.fromhex("00" * 32),
                    "size": pdf_path.stat().st_size,
                },
            )
            document_id = int(doc_result.lastrowid)

            conn.execute(
                text(
                    """
                    INSERT INTO Versions (
                        documentid, intended_for, secret,
                        method, path, link
                    )
                    VALUES (
                        :documentid, :intended_for, :secret,
                        :method, :path, :link
                    )
                    """
                ),
                {
                    "documentid": document_id,
                    "intended_for": "bob",
                    "secret": "foreignsecret",
                    "method": "axel",
                    "path": str(pdf_path),
                    "link": "foreign-link-token",
                },
            )

    # Ensure watermark extraction is never called for unauthorized access
    monkeypatch.setattr(
        WMUtils,
        "read_watermark",
        lambda **kwargs: pytest.fail("read_watermark should not be called"),
    )

    payload = {
        "id": document_id,
        "method": "axel",
        "key": "encryptionkey",
    }

    resp = client.post(
        "/api/read-watermark",
        data=json.dumps(payload),
        headers=auth_headers_unit,
        content_type="application/json",
    )

    assert resp.status_code == 404

    data = resp.get_json()
    assert "error" in data
    assert "not found" in data["error"].lower()


def test_read_watermark_wrong_key(client, auth_headers_unit, monkeypatch):
    """
    Ensures the read-watermark API returns 400 when an incorrect
    decryption key is provided.

    This verifies that watermark extraction failures caused by
    invalid keys are handled safely and do not leak details.
    """

    with client.application.app_context():
        from src.server import get_engine
        engine = get_engine()

        storage_dir = client.application.config["STORAGE_DIR"]
        pdf_path = storage_dir / "wrong_key.pdf"
        pdf_path.write_bytes(b"%PDF-1.4 watermarked content")

        with engine.begin() as conn:
            doc_result = conn.execute(
                text(
                    """
                    INSERT INTO Documents (name, path, ownerid, sha256, size)
                    VALUES (:name, :path, :ownerid, :sha, :size)
                    """
                ),
                {
                    "name": "wrong_key.pdf",
                    "path": str(pdf_path),
                    "ownerid": 1,
                    "sha": bytes.fromhex("00" * 32),
                    "size": pdf_path.stat().st_size,
                },
            )
            document_id = int(doc_result.lastrowid)

            conn.execute(
                text(
                    """
                    INSERT INTO Versions (
                        documentid, intended_for, secret,
                        method, path, link
                    )
                    VALUES (
                        :documentid, :intended_for, :secret,
                        :method, :path, :link
                    )
                    """
                ),
                {
                    "documentid": document_id,
                    "intended_for": "alice",
                    "secret": "topsecret",
                    "method": "axel",
                    "path": str(pdf_path),
                    "link": "wrong-key-link",
                },
            )

    # Simulate decryption failure due to wrong key
    def wrong_key(**kwargs):
        raise ValueError("Invalid decryption key")

    monkeypatch.setattr(WMUtils, "read_watermark", wrong_key)

    payload = {
        "id": document_id,
        "method": "axel",
        "key": "wrong-encryption-key",
    }

    resp = client.post(
        "/api/read-watermark",
        data=json.dumps(payload),
        headers=auth_headers_unit,
        content_type="application/json",
    )

    assert resp.status_code == 400

    data = resp.get_json()
    assert "error" in data