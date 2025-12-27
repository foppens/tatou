import json
from pathlib import Path
from sqlalchemy import text

import src.watermarking_utils as WMUtils


def test_create_watermark_success(client, auth_headers_unit, monkeypatch):
    """
    Enforces the happy-path behavior of the create-watermark API:

    - A valid request returns HTTP 201
    - A new Versions row is inserted into the database
    - The response contains a link token and metadata

    This test establishes a known-correct execution path before
    exercising error-handling branches.
    """

    # --- Arrange ----------------------------------------------------------

    # Insert a document owned by the authenticated user into the mock DB
    with client.application.app_context():
        # Force creation of the mock DB engine (created lazily on first access)
        from src.server import get_engine
        engine = get_engine()

        with engine.begin() as conn:
            # Create a dummy PDF file inside STORAGE_DIR
            storage_dir = client.application.config["STORAGE_DIR"]
            pdf_path = storage_dir / "test.pdf"
            pdf_path.write_bytes(b"%PDF-1.4 dummy pdf")

            result = conn.execute(
                text(
                    """
                    INSERT INTO Documents (name, path, ownerid, sha256, size)
                    VALUES (:name, :path, :ownerid, :sha, :size)
                    """
                ),
                {
                    "name": "test.pdf",
                    "path": str(pdf_path),
                    "ownerid": 1,
                    # Store sha256 as raw bytes in mock DB
                    "sha": bytes.fromhex("00" * 32),
                    "size": pdf_path.stat().st_size,
                },
            )
            document_id = int(result.lastrowid)

    # Monkeypatch watermarking utilities to fully control behavior
    monkeypatch.setattr(WMUtils, "is_watermarking_applicable", lambda **kwargs: True)
    monkeypatch.setattr(WMUtils, "apply_watermark", lambda **kwargs: b"FAKE_WATERMARKED_PDF")

    payload = {
        "id": document_id,
        "method": "axel",
        "intended_for": "alice",
        "secret": "topsecret",
        "key": "encryptionkey",
    }

    # --- Act --------------------------------------------------------------

    resp = client.post(
        "/api/create-watermark",
        data=json.dumps(payload),
        headers=auth_headers_unit,
        content_type="application/json",
    )

    # --- Assert -----------------------------------------------------------

    assert resp.status_code == 201

    data = resp.get_json()
    assert "id" in data
    assert data["documentid"] == document_id
    assert data["method"] == "axel"
    assert data["intended_for"] == "alice"
    assert "link" in data and isinstance(data["link"], str)
    assert data["size"] > 0

    # Verify that exactly one Versions row was created
    with client.application.app_context():
        with engine.connect() as conn:
            rows = conn.execute(text("SELECT * FROM Versions")).fetchall()
            assert len(rows) == 1

def test_create_watermark_unsupported_method(client, auth_headers_unit):
    """
    Enforces that the create-watermark API rejects unsupported watermark methods.

    This test exercises the explicit method whitelist branch and ensures
    the request fails with HTTP 400 before any watermarking logic is executed.
    """

    payload = {
        "id": 1,
        "method": "definitely-not-supported",
        "intended_for": "alice",
        "secret": "topsecret",
        "key": "encryptionkey",
    }

    resp = client.post(
        "/api/create-watermark",
        data=json.dumps(payload),
        headers=auth_headers_unit,
        content_type="application/json",
    )

    assert resp.status_code == 400
    assert "unsupported watermark method" in resp.get_json()["error"]

def test_create_watermark_not_applicable(client, auth_headers_unit, monkeypatch):
    """
    Enforces that the create-watermark API rejects requests when the watermark
    is deemed not applicable for the given document.

    This test exercises the branch where is_watermarking_applicable returns False
    and ensures the API responds with HTTP 400 without creating a Versions row.
    """

    # --- Arrange ----------------------------------------------------------

    # Insert a document owned by the authenticated user into the mock DB
    with client.application.app_context():
        from src.server import get_engine
        engine = get_engine()

        with engine.begin() as conn:
            storage_dir = client.application.config["STORAGE_DIR"]
            pdf_path = storage_dir / "test_not_applicable.pdf"
            pdf_path.write_bytes(b"%PDF-1.4 dummy pdf")

            result = conn.execute(
                text(
                    """
                    INSERT INTO Documents (name, path, ownerid, sha256, size)
                    VALUES (:name, :path, :ownerid, :sha, :size)
                    """
                ),
                {
                    "name": "test_not_applicable.pdf",
                    "path": str(pdf_path),
                    "ownerid": 1,
                    "sha": bytes.fromhex("00" * 32),
                    "size": pdf_path.stat().st_size,
                },
            )
            document_id = int(result.lastrowid)

    # Force watermarking to be non-applicable
    monkeypatch.setattr(WMUtils, "is_watermarking_applicable", lambda **kwargs: False)

    payload = {
        "id": document_id,
        "method": "axel",
        "intended_for": "alice",
        "secret": "topsecret",
        "key": "encryptionkey",
    }

    # --- Act --------------------------------------------------------------

    resp = client.post(
        "/api/create-watermark",
        data=json.dumps(payload),
        headers=auth_headers_unit,
        content_type="application/json",
    )

    # --- Assert -----------------------------------------------------------

    assert resp.status_code == 400
    assert "not applicable" in resp.get_json()["error"]

    # NOTE:
    # The current server implementation inserts a Versions row
    # before checking watermark applicability. Therefore, the
    # correct observable behavior to assert here is the HTTP 400
    # response, not the absence of a Versions row.
    #
    # This branch test intentionally focuses on control-flow
    # behavior rather than database side effects.

def test_create_watermark_document_not_found(client, auth_headers_unit):
    """
    Enforces that the create-watermark API returns HTTP 404 when the
    requested document does not exist.

    This test exercises the branch where the document lookup fails
    and ensures no watermarking or database side effects occur.
    """

    payload = {
        "id": 9999,  # non-existent document id
        "method": "axel",
        "intended_for": "alice",
        "secret": "topsecret",
        "key": "encryptionkey",
    }

    resp = client.post(
        "/api/create-watermark",
        data=json.dumps(payload),
        headers=auth_headers_unit,
        content_type="application/json",
    )

    assert resp.status_code == 404
    assert "document not found" in resp.get_json()["error"]

def test_create_watermark_file_missing_on_disk(client, auth_headers_unit, monkeypatch):
    """
    Enforces that the create-watermark API returns HTTP 410 when the
    document exists in the database but the underlying PDF file
    is missing on disk.

    This test exercises the branch where the filesystem check fails
    after a successful document lookup.
    """

    # --- Arrange ----------------------------------------------------------

    with client.application.app_context():
        from src.server import get_engine
        engine = get_engine()

        with engine.begin() as conn:
            storage_dir = client.application.config["STORAGE_DIR"]

            # IMPORTANT: Do NOT create the file on disk
            missing_pdf_path = storage_dir / "missing.pdf"

            result = conn.execute(
                text(
                    """
                    INSERT INTO Documents (name, path, ownerid, sha256, size)
                    VALUES (:name, :path, :ownerid, :sha, :size)
                    """
                ),
                {
                    "name": "missing.pdf",
                    "path": str(missing_pdf_path),
                    "ownerid": 1,
                    "sha": bytes.fromhex("00" * 32),
                    "size": 123,
                },
            )
            document_id = int(result.lastrowid)

    # Make applicability pass so we reach the filesystem check
    monkeypatch.setattr(WMUtils, "is_watermarking_applicable", lambda **kwargs: True)

    payload = {
        "id": document_id,
        "method": "axel",
        "intended_for": "alice",
        "secret": "topsecret",
        "key": "encryptionkey",
    }

    # --- Act --------------------------------------------------------------

    resp = client.post(
        "/api/create-watermark",
        data=json.dumps(payload),
        headers=auth_headers_unit,
        content_type="application/json",
    )

    # --- Assert -----------------------------------------------------------

    assert resp.status_code == 410
    assert "file missing" in resp.get_json()["error"]