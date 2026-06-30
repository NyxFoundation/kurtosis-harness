"""RLPx crypto primitives — keccak256, secp256k1 ECDH, and eth-flavour ECIES.

ECIES here is the variant devp2p uses for the auth/ack handshake messages:
ephemeral ECDH -> NIST X9.63 concat-KDF(SHA-256) -> AES-128-CTR + HMAC-SHA256,
output = ephemeral_pubkey(65) || iv(16) || ciphertext || tag(32). The optional
shared_mac_data is the two-byte total length prefix used by EIP-8 framing.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from Crypto.Hash import keccak as _keccak

CURVE = ec.SECP256K1()


def keccak256(data: bytes) -> bytes:
    h = _keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


# --- key helpers -----------------------------------------------------------

def gen_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(CURVE)


def privkey_from_int(d: int) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(d, CURVE)


def pubkey_bytes(priv: ec.EllipticCurvePrivateKey) -> bytes:
    """65-byte uncompressed point (0x04 || x || y)."""
    return priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def pubkey_raw64(priv: ec.EllipticCurvePrivateKey) -> bytes:
    """64-byte node-id form (x || y), as used in enode URLs."""
    return pubkey_bytes(priv)[1:]


def pubkey_from_bytes(data: bytes) -> ec.EllipticCurvePublicKey:
    """Accept 64-byte (x||y) or 65-byte (0x04||x||y) uncompressed points."""
    if len(data) == 64:
        data = b"\x04" + data
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, data)


def ecdh_x(priv: ec.EllipticCurvePrivateKey, pub: ec.EllipticCurvePublicKey) -> bytes:
    """ECDH agreement -> the 32-byte shared x coordinate."""
    return priv.exchange(ec.ECDH(), pub)


def priv_scalar(priv: ec.EllipticCurvePrivateKey) -> bytes:
    """The 32-byte private scalar (for the coincurve recoverable-sig backend)."""
    return priv.private_numbers().private_value.to_bytes(32, "big")


def sign_recoverable(priv: ec.EllipticCurvePrivateKey, msg32: bytes) -> bytes:
    """65-byte recoverable ECDSA signature (r || s || v) over the 32-byte msg."""
    from coincurve import PrivateKey as _CCPriv

    return _CCPriv(priv_scalar(priv)).sign_recoverable(msg32, hasher=None)


def recover_pubkey64(sig65: bytes, msg32: bytes) -> bytes:
    """Recover the signer's 64-byte (x||y) pubkey from a recoverable sig."""
    from coincurve import PublicKey as _CCPub

    pub = _CCPub.from_signature_and_message(sig65, msg32, hasher=None)
    return pub.format(compressed=False)[1:]


# --- ECIES -----------------------------------------------------------------

def _concat_kdf(z: bytes, klen: int) -> bytes:
    out = b""
    ctr = 1
    while len(out) < klen:
        out += hashlib.sha256(ctr.to_bytes(4, "big") + z).digest()
        ctr += 1
    return out[:klen]


def ecies_encrypt(remote_pub: ec.EllipticCurvePublicKey, plaintext: bytes,
                  shared_mac_data: bytes = b"") -> bytes:
    eph = gen_private_key()
    z = ecdh_x(eph, remote_pub)
    key = _concat_kdf(z, 32)
    ke, km = key[:16], hashlib.sha256(key[16:32]).digest()
    iv = os.urandom(16)
    enc = Cipher(algorithms.AES(ke), modes.CTR(iv)).encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    tag = hmac.new(km, iv + ct + shared_mac_data, hashlib.sha256).digest()
    return pubkey_bytes(eph) + iv + ct + tag


def ecies_decrypt(priv: ec.EllipticCurvePrivateKey, data: bytes,
                  shared_mac_data: bytes = b"") -> bytes:
    eph_pub = pubkey_from_bytes(data[:65])
    iv, ct, tag = data[65:81], data[81:-32], data[-32:]
    z = ecdh_x(priv, eph_pub)
    key = _concat_kdf(z, 32)
    ke, km = key[:16], hashlib.sha256(key[16:32]).digest()
    expect = hmac.new(km, iv + ct + shared_mac_data, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expect):
        raise ValueError("ECIES MAC mismatch")
    dec = Cipher(algorithms.AES(ke), modes.CTR(iv)).decryptor()
    return dec.update(ct) + dec.finalize()
