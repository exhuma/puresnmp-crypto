import random
from unittest.mock import patch

import pytest

import puresnmp.priv.aes as aes


@pytest.mark.parametrize(
    "unpadded, expected",
    [
        (b"hello", b"hello\x00\x00\x00"),
        (b"hello123", b"hello123"),
    ],
)
def test_pad_packet(unpadded, expected):

    result = aes.pad_packet(unpadded)
    assert result == expected


def test_get_iv():
    result = aes.get_iv(10, 20, b"salt")
    assert result == b"\x00\x00\x00\n\x00\x00\x00\x14\x00\x00\x00\x00salt"


def test_encrypt():
    random.seed(42)
    ciphertext, salt = aes.encrypt_data(
        localised_key=b"xxfoobarfoobarxx",
        engine_id=b"engine",
        engine_boots=10,
        engine_time=20,
        data=b"plaintext",
    )
    assert ciphertext == b"\x01N\xfa@?*\xb1\xeb\x9dp\\\x1c\xe8\x0cW\xba"
    assert salt == b"\x1c\x801\x7f\xa3\xb1y\x9e"


def test_decrypt():
    random.seed(42)
    result = aes.decrypt_data(
        localised_key=b"xxfoobarfoobarxx",
        engine_id=b"engine",
        engine_boots=10,
        engine_time=20,
        salt=b"\x1c\x801\x7f\xa3\xb1y\x9e",
        data=b"\x01N\xfa@?*\xb1\xeb\x9dp\\\x1c\xe8\x0cW\xba",
    )
    assert result[:9] == b"plaintext"


def test_salt_overflow():
    with patch("puresnmp.priv.aes.randint") as randint:
        maxval = 0xffffffffffffffff
        randint.return_value = maxval - 1
        pot = aes.reference_saltpot()
        value = next(pot)
        assert value == maxval - 1
        value = next(pot)
        assert value == 0
