import json
from pathlib import Path

import pytest
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