from sqlalchemy import Table, MetaData, Column, Integer, String, select, insert
from sqlalchemy.exc import SQLAlchemyError
import uuid

from src.mock_db import get_engine


class MockWatermark:
    """
    MockWatermark is a test-only watermarking component.

    Purpose
    - Simulate watermark creation and extraction
    - Persist watermark metadata in a mock database (Versions table)
    - Behave similarly to the real watermarking layer, but without PDFs,
      filesystem access, or Flask dependencies
    """

    def __init__(self):
        self.engine = get_engine()
        self.metadata = MetaData()

        # Define a minimal Versions table matching the real schema fields we care about
        self.versions = Table(
            "Versions",
            self.metadata,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("documentid", Integer, nullable=False),
            Column("link", String, nullable=False),
            Column("intended_for", String, nullable=False),
            Column("secret", String, nullable=False),
            Column("method", String, nullable=False),
        )

        # Reset table for isolated tests
        self.metadata.drop_all(self.engine, tables=[self.versions])
        self.metadata.create_all(self.engine)

        # Error simulation flags (useful for negative tests)
        self.force_create_error = False
        self.force_read_error = False

    def create_watermark(
        self,
        document_id: int,
        method: str,
        intended_for: str,
        secret: str,
    ) -> str:
        """
        Simulate watermark creation.

        This mirrors what /api/create-watermark conceptually does:
        - Validate input
        - Generate a unique link token
        - Store watermark metadata in Versions

        Returns:
            link (str): Unique watermark identifier
        """
        if self.force_create_error:
            raise RuntimeError("Forced error during watermark creation")

        if not all([document_id, method, intended_for, secret]):
            raise ValueError("document_id, method, intended_for, and secret are required")

        link = uuid.uuid4().hex

        stmt = insert(self.versions).values(
            documentid=document_id,
            link=link,
            intended_for=intended_for,
            secret=secret,
            method=method,
        )

        try:
            with self.engine.begin() as conn:
                conn.execute(stmt)
        except SQLAlchemyError as e:
            raise RuntimeError(f"Mock DB error during create_watermark: {e}")

        return link

    def read_watermark(
        self,
        document_id: int,
        method: str,
        intended_for: str,
    ) -> str:
        """
        Simulate watermark extraction.

        This mirrors /api/read-watermark conceptually:
        - Look up a stored watermark
        - Return the embedded secret
        """
        if self.force_read_error:
            raise RuntimeError("Forced error during watermark read")

        stmt = (
            select(self.versions.c.secret)
            .where(self.versions.c.documentid == document_id)
            .where(self.versions.c.method == method)
            .where(self.versions.c.intended_for == intended_for)
        )

        try:
            with self.engine.connect() as conn:
                row = conn.execute(stmt).fetchone()
        except SQLAlchemyError as e:
            raise RuntimeError(f"Mock DB error during read_watermark: {e}")

        if row is None:
            raise KeyError("No watermark found for given parameters")

        return row.secret
