from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, ForeignKey, Text, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
import os

_engine = None
_metadata = MetaData()

# Table definitions
Users = Table(
    "Users", _metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("email", String(128), unique=True, nullable=False),
    Column("login", String(64), unique=True, nullable=False),
    Column("hpassword", String(256), nullable=True),
)

Documents = Table(
    "Documents", _metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(256), nullable=False),
    Column("path", Text, nullable=False),
    Column("ownerid", Integer, ForeignKey("Users.id"), nullable=False),
    Column("sha256", String(64), nullable=True),
    Column("size", Integer, nullable=False),
    Column("creation", String(64), nullable=True),
)

Versions = Table(
    "Versions", _metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("documentid", Integer, ForeignKey("Documents.id"), nullable=False),
    Column("link", String(128), unique=True, nullable=False),
    Column("intended_for", String(64), nullable=False),
    Column("secret", String(128), nullable=False),
    Column("method", String(64), nullable=False),
    Column("position", String(64), nullable=True),
    Column("path", Text, nullable=False),
)

def get_engine():
    """
    Returns a singleton in-memory SQLite engine.
    Ensures all tables are created.
    This database is restricted to TEST_MODE environment to prevent accidental use.
    """
    global _engine
    test_mode = os.getenv("TEST_MODE", "").lower()
    if test_mode not in ("1", "true"):
        raise RuntimeError("Mock database is only available when TEST_MODE is set to '1', 'true', or 'True'.")
    if _engine is None:
        _engine = create_engine('sqlite:///:memory:', echo=False)
        _metadata.create_all(_engine)
    return _engine

def seed_users(users):
    """
    Insert user records into the Users table.
    users: list of dicts, each with 'username' and 'email' keys.
    """
    engine = get_engine()
    with engine.begin() as conn:
        for user in users:
            try:
                conn.execute(Users.insert().values(**user))
            except IntegrityError:
                pass  # Skip duplicates for idempotent seeding

def seed_documents(documents):
    """
    Insert document records into the Documents table.
    documents: list of dicts, each with 'title', 'content', 'owner_id' keys.
    """
    engine = get_engine()
    with engine.begin() as conn:
        # Insert owning user (required for FK + ownership checks)
        conn.execute(
            text(
                """
                INSERT INTO Users (id, email, login, hpassword)
                VALUES (:id, :email, :login, :hpassword)
                """
            ),
            {
                "id": 1,
                "email": "test@example.com",
                "login": "testuser",
                "hpassword": "dummyhash",
            },
        )
        for doc in documents:
            try:
                conn.execute(Documents.insert().values(**doc))
            except IntegrityError:
                pass

def seed_versions(versions):
    """
    Insert version records into the Versions table.
    versions: list of dicts, each with 'document_id', 'version_number', 'content' keys.
    """
    engine = get_engine()
    with engine.begin() as conn:
        for ver in versions:
            try:
                conn.execute(Versions.insert().values(**ver))
            except IntegrityError:
                pass