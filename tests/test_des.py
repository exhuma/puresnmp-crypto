import random
from unittest.mock import patch

import pytest

import puresnmp.priv.des as des


@pytest.mark.parametrize(
    "unpadded, expected",
    [
        (b"hello", b"hello\x00\x00\x00"),
        (b"hello123", b"hello123"),
    ],
)
def test_pad_packet(unpadded, expected):
    result = des.pad_packet(unpadded)
    assert result == expected


def test_encrypt():
    random.seed(42)
    ciphertext, salt = des.encrypt_data(
        localised_key=b"xxfoobarfoobarxx",
        engine_id=b"engine",
        engine_boots=10,
        engine_time=20,
        data=b"plaintext",
    )
    assert ciphertext == b"\x8c\xfdv\xb0\xc1i\xba\xb4\x8fZ\xb4\x13\x02$F\xf0"
    assert salt == b"\x00\x00\x00\n\x00\x00\x00\x9e"


def test_decrypt():
    random.seed(42)
    result = des.decrypt_data(
        localised_key=b"xxfoobarfoobarxx",
        engine_id=b"engine",
        engine_boots=10,
        engine_time=20,
        salt=b"\x00\x00\x00\n\x00\x00\x00\x9e",
        data=b"\x8c\xfdv\xb0\xc1i\xba\xb4\x8fZ\xb4\x13\x02$F\xf0",
    )
    assert result[:9] == b"plaintext"


def test_salt_overflow():
    with patch("puresnmp.priv.des.randint") as randint:
        maxval = 0xffffffff
        randint.return_value = maxval - 1
        pot = des.reference_saltpot()
        value = next(pot)
        assert value == maxval - 1
        value = next(pot)
        assert value == 0
