from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, ForeignKey, Text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
import os

_engine = None
_metadata = MetaData()

# Table definitions
Users = Table(
    'Users', _metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('username', String(64), unique=True, nullable=False),
    Column('email', String(128), unique=True, nullable=False),
)

Documents = Table(
    'Documents', _metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('title', String(256), nullable=False),
    Column('content', Text, nullable=True),
    Column('owner_id', Integer, ForeignKey('Users.id'), nullable=False),
)

Versions = Table(
    'Versions', _metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('document_id', Integer, ForeignKey('Documents.id'), nullable=False),
    Column('version_number', Integer, nullable=False),
    Column('content', Text, nullable=False),
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