from server.src.mock_db import get_engine, seed_users, seed_documents, seed_versions
from sqlalchemy import text

# Get the in-memory engine
engine = get_engine()

# Seed a user
seed_users([{"username": "tester", "email": "tester@example.com"}])

# Seed a document for the user
seed_documents([{"title": "Test Document", "content": "This is a test.", "owner_id": 1}])

# Seed a version for the document
seed_versions([{"document_id": 1, "version_number": 1, "content": "Version 1 content"}])

# Query the tables to verify
with engine.connect() as conn:
    users = conn.execute(text("SELECT id, username, email FROM Users")).fetchall()
    docs = conn.execute(text("SELECT id, title, owner_id FROM Documents")).fetchall()
    versions = conn.execute(text("SELECT id, document_id, version_number, content FROM Versions")).fetchall()

print("Users:", users)
print("Documents:", docs)
print("Versions:", versions)