from __future__ import annotations

from genesis_plugin.crypto_vault.integrity import content_digest


def test_content_digest_is_sha256_of_exact_bytes() -> None:
    assert content_digest(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_content_digest_changes_with_bytes() -> None:
    assert content_digest(b"ACGT") != content_digest(b"ACGT\n")
