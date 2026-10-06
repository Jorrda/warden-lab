from app.utils import digest, mask


def test_digest_is_hex():
    password = "password123"
    assert len(digest(password)) == 64


def test_mask_keeps_the_ends():
    assert mask("abcdefghijkl") == "abcd...kl"
