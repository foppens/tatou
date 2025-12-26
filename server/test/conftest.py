import io
import pytest
import requests
import uuid
from reportlab.pdfgen import canvas
from src.server import app
from sqlalchemy import text
import tempfile
from pathlib import Path

API_URL = "http://server:5000/api"

@pytest.fixture
def user1():
    unique = uuid.uuid4().hex[:8]
    user = {
        "login": f"user1_{unique}",
        "password": "testpass123",
        "email": f"user1_{unique}@example.com"
    }
    requests.post(f"{API_URL}/create-user", json=user)
    return user

@pytest.fixture
def user2():
    unique = uuid.uuid4().hex[:8]
    user = {
        "login": f"user2_{unique}",
        "password": "testpass123",
        "email": f"user2_{unique}@example.com"
    }
    requests.post(f"{API_URL}/create-user", json=user)
    return user

@pytest.fixture
def auth_headers(user1):
    r = requests.post(f"{API_URL}/login", json={"email": user1["email"], "password": user1["password"]})
    token = r.json()["token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def auth_client(user1):
    app.config["TESTING"] = True
    with app.test_client() as client:
        #Get token through login
        resp = client.post("/api/login", json={"email": user1["email"], "password": user1["password"]})
        token = resp.get_json()["token"]
        client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {token}"
        yield client

@pytest.fixture
def uploaded_document(auth_headers):
    # Using reportlab to create a real pdf with multiple pages
    pdf_buffer = io.BytesIO()
    c = canvas.Canvas(pdf_buffer)
    c.drawString(100, 750, "This is a test PDF.")
    c.showPage()
    c.drawString(100, 750, "Second page.")
    c.showPage()
    c.save()
    pdf_buffer.seek(0)

    files = {
        "file": ("test.pdf", pdf_buffer, "application/pdf"),
        "name": (None, "test.pdf")
    }
    r = requests.post(f"{API_URL}/upload-document", files=files, headers=auth_headers)
    assert r.status_code == 201
    return r.json()

@pytest.fixture
def watermarked_document(auth_headers, uploaded_document):
    import uuid
    unique = uuid.uuid4().hex[:8]
    watermark_payload = {
        "method": "axel",
        "position": "top-left",
        "key": "testkey123",
        "secret": f"mysecret_{unique}",
        "intended_for": f"recipient_{unique}@example.com",
        "id": uploaded_document["id"]
    }
    r2 = requests.post(f"{API_URL}/create-watermark", json=watermark_payload, headers=auth_headers)
    assert r2.status_code in (200, 201)
    watermark_response = r2.json()
    # Download the watermarked PDF using the link
    link = watermark_response["link"]
    if link.startswith("http"):
        download_url = link
    else:
        download_url = f"{API_URL}/get-version/{link}"
    r3 = requests.get(download_url)
    assert r3.status_code == 200
    watermarked_pdf_bytes = r3.content

    result = uploaded_document.copy()
    result["watermark"] = watermark_payload
    result["watermark_response"] = watermark_response
    result["watermarked_pdf_bytes"] = watermarked_pdf_bytes
    return result

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

@pytest.fixture(scope="function")
def ensure_group19_document(user1):
    """Ensure the Group_19 document exists in the database for RMAP tests."""
    from server import get_engine
    engine = get_engine()
    owner_email = user1["email"]
    ownerid = 1

    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT id FROM Users WHERE email=:email LIMIT 1"),
            {"email": owner_email},
        ).first()
        if row:
            ownerid = row[0]

        result = conn.execute(
            text("SELECT id FROM Documents WHERE name=:n LIMIT 1"),
            {"n": "Group_19"},
        ).first()
        if not result:
            conn.execute(
                text(
                    "INSERT INTO Documents (name, path, ownerid, sha256, size) "
                    "VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)"
                ),
                {
                    "name": "Group_19",
                    "path": "/tmp/group_19.pdf",
                    "ownerid": ownerid,
                    "sha256hex": "0" * 64,
                    "size": 12345,
                },
            )

# List of external group URLs
EXTERNAL_GROUPS = {
    "Group_03": "http://10.11.12.13:5000",
    "Group_04": "http://10.11.12.19:5000",
    "Group_07": "http://10.11.12.14:5000",
    "Group_08": "http://10.11.12.7:5000",
    "Group_09": "http://10.11.12.10:5000",
    "Group_14": "http://10.11.12.18:5000",
    "Group_19": "http://server:5000",
    "Group_20": "http://10.11.12.9:5000",
    "Group_22": "http://10.11.12.8:5000",
    "Group_24": "http://10.11.12.15:5000",
    "Group_26": "http://10.11.12.12:5000",
}

def is_reachable(url, timeout=2):
    """Return True if the given base URL responds, False otherwise."""
    try:
        r = requests.get(url, timeout=timeout)
        return r.status_code < 500
    except Exception:
        return False

@pytest.fixture
def skip_if_group_unreachable(request):
    """Fixture to skip a test if the external group is unreachable."""
    group_name = getattr(request, 'param', None)
    if group_name and group_name in EXTERNAL_GROUPS:
        base_url = EXTERNAL_GROUPS[group_name]
        if not is_reachable(base_url):
            pytest.skip(f"Skipping {group_name}: {base_url} not reachable")

@pytest.fixture
def isolated_client():
    """
    Returns a Flask test client and a temporary STORAGE_DIR.
    Use this for load-plugin tests to avoid interfering with real documents.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        storage_root = Path(tmpdir)
        # Configure the Flask client
        app.config["TESTING"] = True
        client = app.test_client()
        # Patch STORAGE_DIR for this client only
        client.application.config["STORAGE_DIR"] = str(storage_root)
        yield client, storage_root