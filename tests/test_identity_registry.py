
import pytest

from privacy.identity_registry import IdentityRegistry


@pytest.fixture
def registry(tmp_path):
    return IdentityRegistry(
        db_path=tmp_path / "identities.db"
    )


def test_linked_accounts_resolve_to_same_identity(registry):
    registry.register("researcher-a", "group-001")
    registry.register("researcher-b", "group-001")

    assert registry.resolve("researcher-a") == "group-001"
    assert registry.resolve("researcher-b") == "group-001"


def test_unknown_requester_is_rejected(registry):
    with pytest.raises(
        PermissionError,
        match="not registered",
    ):
        registry.resolve("unknown-researcher")


def test_requester_mapping_cannot_be_overwritten(registry):
    registry.register("researcher-a", "group-001")

    with pytest.raises(ValueError, match="already"):
        registry.register("researcher-a", "group-002")

    assert registry.resolve("researcher-a") == "group-001"


def test_blank_ids_are_rejected(registry):
    with pytest.raises(ValueError):
        registry.register("", "group-001")

    with pytest.raises(ValueError):
        registry.register("researcher-a", " ")
