from __future__ import annotations

from genesis_plugin import StorageVault, VerifyResult


def test_public_exports() -> None:
    assert StorageVault.__name__ == "StorageVault"
    assert VerifyResult.__name__ == "VerifyResult"
