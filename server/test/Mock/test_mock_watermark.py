import pytest
from src.mock_watermark import MockWatermark


@pytest.fixture
def mock_wm():
    """
    Provides a fresh MockWatermark instance per test.

    This ensures:
    - Isolated in-memory database
    - No cross-test state leakage
    """
    return MockWatermark()


def test_create_watermark_success():
    """
    Enforces that a watermark can be created successfully
    and that a non-empty link token is returned.
    """
    wm = MockWatermark()

    link = wm.create_watermark(
        document_id=1,
        method="axel",
        intended_for="tester",
        secret="secret123",
    )

    assert isinstance(link, str)
    assert len(link) > 0


def test_read_watermark_success(mock_wm):
    """
    Enforces that a previously created watermark
    can be read and returns the correct embedded secret.
    """
    link = mock_wm.create_watermark(
        document_id=1,
        method="axel",
        intended_for="tester",
        secret="top-secret",
    )

    secret = mock_wm.read_watermark(
        document_id=1,
        method="axel",
        intended_for="tester",
    )

    assert secret == "top-secret"


def test_create_watermark_missing_fields():
    """
    Enforces input validation during watermark creation.
    Missing required fields must raise ValueError.
    """
    wm = MockWatermark()

    with pytest.raises(ValueError):
        wm.create_watermark(
            document_id=None,
            method="axel",
            intended_for="tester",
            secret="secret",
        )


def test_read_watermark_not_found(mock_wm):
    """
    Enforces correct error handling when attempting to
    read a watermark that does not exist.
    """
    with pytest.raises(KeyError):
        mock_wm.read_watermark(
            document_id=999,
            method="axel",
            intended_for="nobody",
        )


def test_forced_create_error_branch(mock_wm):
    """
    Enforces the internal failure branch during watermark creation.
    This simulates unexpected internal processing errors.
    """
    mock_wm.force_create_error = True

    with pytest.raises(RuntimeError):
        mock_wm.create_watermark(
            document_id=2,
            method="axel",
            intended_for="tester2",
            secret="secret456",
        )


def test_forced_read_error_branch(mock_wm):
    """
    Enforces the internal failure branch during watermark reading.
    This simulates unexpected internal processing errors.
    """
    mock_wm.create_watermark(
        document_id=1,
        method="axel",
        intended_for="tester",
        secret="secret123",
    )

    mock_wm.force_read_error = True

    with pytest.raises(RuntimeError):
        mock_wm.read_watermark(
            document_id=1,
            method="axel",
            intended_for="tester",
        )