#!/usr/bin/env python3
"""An independent verifier for Kavach evidence and credentials.

Written from docs/specs/evidence-bundle.md and docs/specs/credential-format.md
alone, in a different language from the implementation it checks, with the
standard library only (its own SHA-512 use is hashlib; Ed25519, X25519 and
AES-GCM are written out below from RFC 8032, RFC 7748 and NIST SP 800-38D).

It is for conformance checking and audit. It is **not** for handling secrets
in production: the credential commands take a provider's private key, and
pure-Python big-integer arithmetic is not constant time.

    kavach_verify.py bundle DIR --keys KEYS.json [--expect-checkpoint FILE]
                                 [--now RFC3339] [--dev] [--allow-warnings]
    kavach_verify.py credential VECTOR.json [--now UNIX_SECONDS]
    kavach_verify.py mandate VECTOR.json
    kavach_verify.py jcs VECTOR.json
    kavach_verify.py checkpoints VECTOR.json

Exit status: 0 verified, 2 verified with warnings, 1 does not verify.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import stat
import sys
from datetime import datetime, timedelta, timezone

MAX_LINE = 1_048_576
MAX_SAFE = 2**53 - 1
GENESIS = "0" * 64
EVENT_DIGEST_PREFIX = "sha256-jcs-v1:"
ZERO_HASH = GENESIS


class Refused(Exception):
    """The input does not verify, or is malformed. `rule` names the rule that
    refused it, for the vectors that say which rule a token breaks."""

    def __init__(self, message, rule=None):
        super().__init__(message)
        self.rule = rule


# --------------------------------------------------------------------------
# Strict JSON and canonical form (spec 2.1, 2.2)
# --------------------------------------------------------------------------

def _pairs(items):
    out = {}
    for key, value in items:
        if key in out:
            raise Refused(f"duplicate member name {key!r}", "duplicate")
        out[key] = value
    return out


def _no_number(text):
    raise Refused(f"number {text} is not an integer", "number")


def _check_numbers(value):
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE:
            raise Refused(f"integer {value} is outside the safe range", "number")
    elif isinstance(value, list):
        for item in value:
            _check_numbers(item)
    elif isinstance(value, dict):
        for item in value.values():
            _check_numbers(item)


def loads(text):
    """Parses JSON, refusing duplicate names, non-integers and big integers."""
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_float=_no_number,
            parse_constant=_no_number,
        )
    except json.JSONDecodeError as error:
        raise Refused(f"not JSON: {error}") from None
    _check_numbers(value)
    return value


_ESCAPES = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r",
            0x22: '\\"', 0x5C: "\\\\"}


def _jstr(text):
    out = ['"']
    for ch in text:
        code = ord(ch)
        if code in _ESCAPES:
            out.append(_ESCAPES[code])
        elif code < 0x20:
            out.append("\\u%04x" % code)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(value):
    """RFC 8785 canonical form of the JSON values this spec uses."""
    parts = []

    def enc(v):
        if v is None:
            parts.append("null")
        elif v is True:
            parts.append("true")
        elif v is False:
            parts.append("false")
        elif isinstance(v, int):
            if abs(v) > MAX_SAFE:
                raise Refused(f"integer {v} is outside the safe range")
            parts.append(str(v))
        elif isinstance(v, str):
            parts.append(_jstr(v))
        elif isinstance(v, list):
            parts.append("[")
            for i, item in enumerate(v):
                if i:
                    parts.append(",")
                enc(item)
            parts.append("]")
        elif isinstance(v, dict):
            parts.append("{")
            keys = sorted(v, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
            for i, key in enumerate(keys):
                if i:
                    parts.append(",")
                parts.append(_jstr(key))
                parts.append(":")
                enc(v[key])
            parts.append("}")
        else:
            raise Refused(f"cannot canonicalise {type(v).__name__}")

    enc(value)
    try:
        return "".join(parts).encode("utf-8")
    except UnicodeEncodeError:
        raise Refused("a string is not valid Unicode") from None


# --------------------------------------------------------------------------
# Encodings
# --------------------------------------------------------------------------

_HASH = re.compile(r"^[0-9a-f]{64}$")
_SIG = re.compile(r"^[0-9a-f]{128}$")
_TIME = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$"
)
_REASON = re.compile(r"^[a-z0-9_]{1,64}$")


def is_hash(value):
    return isinstance(value, str) and _HASH.match(value) is not None


def is_sig(value):
    return isinstance(value, str) and _SIG.match(value) is not None


def parse_time(text, what="time"):
    """Returns (datetime, microsecond-truncated six-digit fraction)."""
    if not isinstance(text, str):
        raise Refused(f"{what} is not a string")
    m = _TIME.match(text)
    if not m:
        raise Refused(f"{what} {text!r} is not RFC 3339 UTC with a Z suffix")
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    frac = (m.group(7) or "").ljust(6, "0")[:6]
    try:
        when = datetime(y, mo, d, h, mi, s, int(frac), tzinfo=timezone.utc)
    except ValueError:
        raise Refused(f"{what} {text!r} is not a time") from None
    return when


def six_digit_time(when):
    return when.strftime("%Y-%m-%dT%H:%M:%S.") + "%06dZ" % when.microsecond


def b64url_decode(text, what="base64url"):
    if not isinstance(text, str) or not re.match(r"^[A-Za-z0-9_-]*$", text):
        raise Refused(f"{what}: not base64url without padding", "base64")
    if len(text) % 4 == 1:
        raise Refused(f"{what}: impossible length", "base64")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != text:
        raise Refused(f"{what}: non-zero trailing bits", "base64")
    return raw


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


# --------------------------------------------------------------------------
# Ed25519 (RFC 8032, section 5.1 and the reference code of section 6)
# --------------------------------------------------------------------------

_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _inv(x):
    return pow(x, _P - 2, _P)


def _padd(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % _P
    B = (a[1] + a[0]) * (b[1] + b[0]) % _P
    C = 2 * a[3] * b[3] * _D % _P
    D = 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _pmul(s, point):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _padd(q, point)
        point = _padd(point, point)
        s >>= 1
    return q


def _peq(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decompress(raw):
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def ed25519_verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decompress(public)
    r = _decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _Q
    return _peq(_pmul(s, _G), _padd(r, _pmul(h, a)))


# --------------------------------------------------------------------------
# X25519 (RFC 7748, section 5) and AES-256-GCM (FIPS 197, SP 800-38D)
# --------------------------------------------------------------------------

def x25519(k, u):
    kk = bytearray(k)
    kk[0] &= 248
    kk[31] &= 127
    kk[31] |= 64
    k_int = int.from_bytes(kk, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        kt = (k_int >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + 121665 * e) % _P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * _inv(z2) % _P).to_bytes(32, "little")


def _gmul(a, b):
    out = 0
    while b:
        if b & 1:
            out ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return out


def _sbox():
    inverse = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _gmul(a, b) == 1:
                inverse[a] = b
                break
    box = []
    for x in range(256):
        b = inverse[x]
        s = b
        for i in range(1, 5):
            s ^= ((b << i) | (b >> (8 - i))) & 0xFF
        box.append(s ^ 0x63)
    return box


_SBOX = _sbox()


def _expand_key(key):
    if len(key) != 32:
        raise Refused("AES-256 needs a 32-byte key")
    words = [list(key[4 * i:4 * i + 4]) for i in range(8)]
    rcon = 1
    for i in range(8, 60):
        t = list(words[i - 1])
        if i % 8 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _gmul(rcon, 2)
        elif i % 8 == 4:
            t = [_SBOX[b] for b in t]
        words.append([a ^ b for a, b in zip(words[i - 8], t)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(15)]


def _aes_encrypt_block(round_keys, block):
    state = [b ^ k for b, k in zip(block, round_keys[0])]
    for rnd in range(1, 15):
        state = [_SBOX[b] for b in state]
        state = [state[(r + 4 * ((c + r) % 4))] for c in range(4) for r in range(4)]
        if rnd != 14:
            mixed = []
            for c in range(4):
                a0, a1, a2, a3 = state[4 * c:4 * c + 4]
                mixed += [
                    _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3,
                    a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3,
                    a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3),
                    _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2),
                ]
            state = mixed
        state = [b ^ k for b, k in zip(state, round_keys[rnd])]
    return bytes(state)


def _ghash_mul(x, y):
    z, v = 0, y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ (0xE1 << 120) if v & 1 else v >> 1
    return z


def _ghash(h, aad, ciphertext):
    def blocks(data):
        for i in range(0, len(data), 16):
            yield int.from_bytes(data[i:i + 16].ljust(16, b"\0"), "big")

    y = 0
    for block in list(blocks(aad)) + list(blocks(ciphertext)):
        y = _ghash_mul(y ^ block, h)
    lengths = (len(aad) * 8) << 64 | (len(ciphertext) * 8)
    return _ghash_mul(y ^ lengths, h)


def aes256_gcm_open(key, iv, aad, ciphertext, tag):
    """Returns the plaintext, or raises Refused if the tag does not authenticate."""
    if len(iv) != 12 or len(tag) != 16:
        raise Refused("GCM needs a 96-bit IV and a 128-bit tag")
    round_keys = _expand_key(key)
    h = int.from_bytes(_aes_encrypt_block(round_keys, bytes(16)), "big")
    j0 = iv + b"\x00\x00\x00\x01"
    expect = _ghash(h, aad, ciphertext) ^ int.from_bytes(_aes_encrypt_block(round_keys, j0), "big")
    if not hmac.compare_digest(expect.to_bytes(16, "big"), tag):
        raise Refused("the ciphertext does not authenticate")
    out = bytearray()
    counter = int.from_bytes(j0, "big")
    for i in range(0, len(ciphertext), 16):
        counter = (counter & ~0xFFFFFFFF) | ((counter + 1) & 0xFFFFFFFF)
        stream = _aes_encrypt_block(round_keys, counter.to_bytes(16, "big"))
        out += bytes(a ^ b for a, b in zip(ciphertext[i:i + 16], stream))
    return bytes(out)


# --------------------------------------------------------------------------
# Trusted keys (spec 8)
# --------------------------------------------------------------------------

class Key:
    def __init__(self, kid, public, valid_until_seq, not_before, not_after):
        self.kid = kid
        self.public = public
        self.valid_until_seq = valid_until_seq
        self.not_before = not_before
        self.not_after = not_after


def load_keys(path):
    with open(path, "r", encoding="utf-8") as handle:
        doc = loads(handle.read())
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
        raise Refused("the keys file must be an object with a keys array")
    keys = {}
    for entry in doc["keys"]:
        if not isinstance(entry, dict):
            raise Refused("a key entry is not an object")
        if entry.get("alg") != "Ed25519":
            raise Refused(f"key {entry.get('kid')!r}: alg must be Ed25519")
        kid, public = entry.get("kid"), entry.get("public_key")
        if not isinstance(kid, str) or not re.match(r"^[0-9a-f]{64}$", str(public)):
            raise Refused("a key entry needs kid and a 64-hex public_key")
        until = entry.get("valid_until_seq")
        if until is not None and (isinstance(until, bool) or not isinstance(until, int)):
            raise Refused(f"key {kid}: valid_until_seq must be an integer")
        nb = parse_time(entry["not_before"], "not_before") if "not_before" in entry else None
        na = parse_time(entry["not_after"], "not_after") if "not_after" in entry else None
        keys[kid] = Key(kid, bytes.fromhex(public), until, nb, na)
    return keys


# --------------------------------------------------------------------------
# The bundle (spec 3 to 9)
# --------------------------------------------------------------------------

RECORD_PREFIX = b"kavach-evidence-v2"
RECORD_SIG = b"kavach-agent-evidence-sig-v1:"
OUTCOME_SIG_V1 = b"kavach-agent-outcome-sig-v1:"
OUTCOME_SIG_V2 = b"kavach-agent-outcome-sig-v2:"
CHECKPOINT_PREFIX = b"kavach-evidence-checkpoint-v1"
CHECKPOINT_SIG = b"kavach-evidence-checkpoint-v1:"
MANIFEST_PREFIX = b"kavach-evidence-bundle-v1"
MANIFEST_SIG = b"kavach-evidence-bundle-v1:"

KINDS = {
    1: {"agent_decision"},
    2: {"agent_decision", "mandate_revocation"},
    3: {"agent_decision", "mandate_revocation", "agent_state"},
    4: {"agent_decision", "mandate_revocation", "agent_state"},
}
RESOLUTION_SIG = b"kavach-outcome-resolution-sig-v1:"
RESOLUTION_STATES = {"confirmed_delivered", "confirmed_not_delivered", "ambiguous"}
CONFIRMED = {"confirmed_delivered", "confirmed_not_delivered"}
RESOLUTION_SOURCES = {"provider_status", "operator_attested", "conflict_resolution", "reconciler"}
STATES = ["active", "restricted", "quarantined", "revoked"]
REASON_CODES = {"rogue_behaviour", "compromise_suspected", "policy_violation",
                "customer_complaint", "operator_request", "reviewed", "other"}
OUTCOMES = {"delivered", "failed", "refused", "not_executed", "unknown"}
FILES = ["manifest.json", "records.jsonl", "outcomes.jsonl", "checkpoints.jsonl"]
RESOLUTIONS = "resolutions.jsonl"
RESOLUTIONS_SINCE = 4


def _members(obj, required, optional=(), what="object"):
    if not isinstance(obj, dict):
        raise Refused(f"{what} is not an object")
    missing = [m for m in required if m not in obj]
    if missing:
        raise Refused(f"{what} lacks {missing}", "member")
    extra = [m for m in obj if m not in required and m not in optional]
    if extra:
        raise Refused(f"{what} has members it must not have: {extra}", "member")


def _int(value, what, low=None):
    if isinstance(value, bool) or not isinstance(value, int):
        raise Refused(f"{what} is not an integer")
    if low is not None and value < low:
        raise Refused(f"{what} is below {low}")
    return value


def _str(value, what):
    if not isinstance(value, str):
        raise Refused(f"{what} is not a string")
    return value


def _lines(data, name):
    if not data:
        return []
    if not data.endswith(b"\n"):
        raise Refused(f"{name}: the last line has no line feed")
    out = data.split(b"\n")[:-1]
    for number, line in enumerate(out, 1):
        if len(line) > MAX_LINE:
            raise Refused(f"{name} line {number}: longer than {MAX_LINE} bytes")
    return out


def _parse_line(raw, name, number):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused(f"{name} line {number}: not UTF-8") from None
    try:
        return loads(text)
    except Refused as error:
        raise Refused(f"{name} line {number}: {error}") from None


def _signed(prefix, value):
    return prefix + value.encode("ascii")


class Verifier:
    def __init__(self, keys, dev=False, now=None):
        self.keys = keys
        self.dev = dev
        self.now = now or datetime.now(timezone.utc)
        self.warnings = []
        self.kept_seq = None

    # -- keys and limits ---------------------------------------------------
    def _key(self, kid, what):
        key = self.keys.get(kid)
        if key is None:
            raise Refused(f"{what}: key {kid!r} is not trusted")
        if not self.dev and kid.startswith("dev-"):
            raise Refused(f"{what}: development key {kid!r} outside a development stack")
        return key

    def _check_sig(self, kid, message, sig, what):
        key = self._key(kid, what)
        if not is_sig(sig) or not ed25519_verify(key.public, message, bytes.fromhex(sig)):
            raise Refused(f"{what}: signature does not verify")

    def _limits(self, kid, seq, when, what):
        key = self.keys[kid]
        if key.valid_until_seq is not None and seq > key.valid_until_seq:
            if self.kept_seq is None or seq > self.kept_seq:
                raise Refused(
                    f"{what}: key {kid} signed for record {seq}, after its limit "
                    f"{key.valid_until_seq}, and no kept checkpoint covers it"
                )
        if key.not_before is not None and when < key.not_before:
            raise Refused(f"{what}: key {kid} signed before its validity period")
        if key.not_after is not None and when >= key.not_after:
            raise Refused(f"{what}: key {kid} signed after its validity period")

    # -- the manifest --------------------------------------------------------
    def manifest(self, doc):
        signed = "key_id" in doc or "sig" in doc
        required = ["format", "version", "tenant_id", "partition_id", "chain", "segment",
                    "files", "exported_at", "exporter", "hash"]
        optional = ["key_id", "sig"]
        _members(doc, required, optional, "manifest")
        if doc["format"] != "kavach-evidence-bundle":
            raise Refused("manifest: not a Kavach evidence bundle")
        if _int(doc["version"], "manifest version") not in KINDS:
            raise Refused(f"manifest: unknown bundle version {doc['version']}")
        _str(doc["tenant_id"], "tenant_id")
        _int(doc["partition_id"], "partition_id")
        _str(doc["chain"], "chain")
        seg = doc["segment"]
        _members(seg, ["after_seq", "after_hash", "last_seq", "head_hash"], what="segment")
        after, last = _int(seg["after_seq"], "after_seq", 0), _int(seg["last_seq"], "last_seq", 0)
        if last < after:
            raise Refused("manifest: the segment bounds are out of order")
        if not is_hash(seg["after_hash"]) or not is_hash(seg["head_hash"]):
            raise Refused("manifest: segment hashes must be 64 lowercase hex")
        if (after == 0) != (seg["after_hash"] == GENESIS):
            raise Refused("manifest: after_seq 0 and the genesis hash go together")
        if last == after and seg["head_hash"] != seg["after_hash"]:
            raise Refused("manifest: an empty segment must end where it starts")
        files = doc["files"]
        version = doc["version"]
        listed = ["records", "outcomes", "checkpoints"]
        if version >= RESOLUTIONS_SINCE:
            listed.append("resolutions")
        _members(files, listed, what="files")
        for name in listed:
            _members(files[name], ["sha256", "count"], what=f"files.{name}")
            if not is_hash(files[name]["sha256"]):
                raise Refused(f"manifest: files.{name}.sha256 is not 64 lowercase hex")
            _int(files[name]["count"], f"files.{name}.count", 0)
        if files["records"]["count"] != last - after:
            raise Refused("manifest: the record count does not match the segment")
        _members(doc["exporter"], ["tool", "version"], what="exporter")
        exported = parse_time(doc["exported_at"], "exported_at")
        if ("key_id" in doc) != ("sig" in doc):
            raise Refused("manifest: key_id and sig go together")
        if not is_hash(doc["hash"]):
            raise Refused("manifest: hash is not 64 lowercase hex")
        payload = {k: v for k, v in doc.items() if k not in ("hash", "sig")}
        expect = hashlib.sha256(MANIFEST_PREFIX + jcs(payload)).hexdigest()
        if expect != doc["hash"]:
            raise Refused("manifest: hash does not match its content")
        if signed:
            kid = _str(doc["key_id"], "manifest key_id")
            if not (kid.startswith("export-") or kid.startswith("dev-export-")):
                raise Refused(f"manifest: {kid!r} is not an export key")
            self._check_sig(kid, _signed(MANIFEST_SIG, doc["hash"]), doc["sig"], "manifest")
        else:
            self.warnings.append({"kind": "unsigned", "detail": "the manifest is unsigned"})
        return exported

    # -- records -------------------------------------------------------------
    def records(self, lines, manifest):
        seg, version = manifest["segment"], manifest["version"]
        expected_seq, prev = seg["after_seq"] + 1, seg["after_hash"]
        out = []
        for number, raw in enumerate(lines, 1):
            where = f"records.jsonl line {number}"
            rec = _parse_line(raw, "records.jsonl", number)
            if not isinstance(rec, dict):
                raise Refused(f"{where}: not an object")
            for member in ("kind", "tenant_id", "key_id", "hash_alg", "prev_hash", "hash", "sig",
                           "time_sync"):
                if member not in rec:
                    raise Refused(f"{where}: lacks {member}")
            kind = _str(rec["kind"], f"{where}: kind")
            if kind not in KINDS[version]:
                raise Refused(f"{where}: kind {kind!r} is not in the registry for version {version}")
            if rec["tenant_id"] != manifest["tenant_id"]:
                raise Refused(f"{where}: another tenant")
            if _int(rec.get("partition_id"), "partition_id") != manifest["partition_id"]:
                raise Refused(f"{where}: another partition")
            _members(rec["time_sync"], ["status", "max_error_ms"], what=f"{where}: time_sync")
            kid = _str(rec["key_id"], f"{where}: key_id")
            if not self.dev and (kid.startswith("dev-") or rec["time_sync"]["status"] == "dev_fixed"):
                raise Refused(f"{where}: development evidence outside a development stack")
            if rec["hash_alg"] != "v2":
                raise Refused(f"{where}: hash_alg is not v2")
            seq = _int(rec.get("seq"), "seq", 1)
            if seq != expected_seq:
                raise Refused(f"{where}: seq {seq}, expected {expected_seq}")
            if rec["prev_hash"] != prev:
                raise Refused(f"{where}: does not link to the record before it")
            if not is_hash(rec["hash"]):
                raise Refused(f"{where}: hash is not 64 lowercase hex")
            payload = {k: v for k, v in rec.items() if k not in ("hash", "sig")}
            expect = hashlib.sha256(RECORD_PREFIX + rec["prev_hash"].encode("ascii") + jcs(payload)).hexdigest()
            if expect != rec["hash"]:
                raise Refused(f"{where}: hash does not match its content")
            self._check_sig(kid, _signed(RECORD_SIG, rec["hash"]), rec["sig"], where)
            when = parse_time(
                rec["recorded_at"] if kind in ("mandate_revocation", "agent_state") else rec.get("ts"),
                f"{where}: time")
            self._limits(kid, seq, when, where)
            if kind == "agent_decision":
                for member in ("credential_id", "returned_decision", "credential_expires_at"):
                    if member not in rec:
                        raise Refused(f"{where}: lacks {member}")
            if kind == "mandate_revocation":
                self._event_digest(rec, where)
            if kind == "agent_state":
                self._agent_state_form(rec, where)
            prev, expected_seq = rec["hash"], expected_seq + 1
            out.append(rec)
        if prev != seg["head_hash"] or expected_seq - 1 != seg["last_seq"]:
            raise Refused("records.jsonl: the records do not end at the manifest's head")
        return out

    @staticmethod
    def _agent_state_form(rec, where):
        """Spec 4.5: the rules a hash and a signature do not establish."""
        for member in ("agent_id", "change_no", "from_state", "to_state", "reason_code",
                       "reason_digest", "changed_by", "approved_by", "changed_at", "recorded_at"):
            if member not in rec:
                raise Refused(f"{where}: lacks {member}")
        def bad(reason):
            raise Refused(f"{where}: malformed record: {reason}")
        if not isinstance(rec["agent_id"], str) or not rec["agent_id"]:
            bad("agent_id is not a string")
        if isinstance(rec["change_no"], bool) or not isinstance(rec["change_no"], int) \
                or rec["change_no"] < 1:
            bad("change_no starts at 1")
        if rec["from_state"] not in STATES or rec["to_state"] not in STATES:
            bad("a state is not in the set")
        if rec["from_state"] == rec["to_state"]:
            bad("a change from a state to itself is not a change")
        if rec["from_state"] == "revoked":
            bad("a revoked agent is never changed")
        if rec["reason_code"] not in REASON_CODES:
            bad("reason_code is not in the closed set")
        digest = rec["reason_digest"]
        if digest is not None and not (
                isinstance(digest, str) and digest.startswith("mac:") and is_hash(digest[4:])):
            bad("reason_digest is not a well-formed digest")
        parse_time(rec["changed_at"], f"{where}: changed_at")
        loosens = STATES.index(rec["to_state"]) < STATES.index(rec["from_state"])
        approver = rec["approved_by"]
        if loosens:
            if not (isinstance(approver, str) and approver and approver != rec["changed_by"]):
                bad("a loosening needs an approver other than the changer")
        elif approver is not None:
            bad("a change that tightens names no approver")
        if "change_request_id" in rec:
            request = rec["change_request_id"]
            if not (isinstance(request, str) and 1 <= len(request) <= 128
                    and not any(ord(c) < 32 or ord(c) == 127 for c in request)):
                bad("change_request_id is not a plain identifier of 1 to 128 characters")
            if not loosens:
                bad("only a loosening is carried out by a change request")

    @staticmethod
    def _event_digest(rec, where):
        """Exactly one well-formed digest: event_digest (tagged) or legacy event_sha256."""
        tagged, legacy = rec.get("event_digest"), rec.get("event_sha256")
        ok = False
        if (tagged is None) != (legacy is None):
            if tagged is not None:
                ok = (isinstance(tagged, str) and tagged.startswith(EVENT_DIGEST_PREFIX)
                      and is_hash(tagged[len(EVENT_DIGEST_PREFIX):]))
            else:
                ok = is_hash(legacy)
        if not ok:
            raise Refused(f"{where}: malformed record: exactly one well-formed event digest "
                          "(event_digest or event_sha256) is required")

    # -- outcomes ------------------------------------------------------------
    def outcomes(self, lines, records, manifest):
        parsed = []
        for number, raw in enumerate(lines, 1):
            out = _parse_line(raw, "outcomes.jsonl", number)
            _members(out, ["tenant_id", "credential_id", "record_hash", "outcome", "ts", "key_id",
                           "sig"], ["reason"], f"outcomes.jsonl line {number}")
            parsed.append(out)
        index = 0
        missing, unknown = [], []
        for rec in records:
            if rec["kind"] != "agent_decision" or rec["credential_id"] is None:
                continue
            nxt = parsed[index] if index < len(parsed) else None
            if nxt is None or nxt["credential_id"] != rec["credential_id"]:
                if rec["returned_decision"] in ("PASS", "ALERT"):
                    expires = rec["credential_expires_at"]
                    if expires is None or parse_time(expires, "credential_expires_at") <= self.now:
                        missing.append(rec["credential_id"])
                continue
            index += 1
            where = f"outcomes.jsonl line {index}"
            if nxt["tenant_id"] != manifest["tenant_id"] or nxt["record_hash"] != rec["hash"]:
                raise Refused(f"{where}: names another record")
            kid = _str(nxt["key_id"], f"{where}: key_id")
            if not self.dev and kid.startswith("dev-"):
                raise Refused(f"{where}: signed with a development key")
            if nxt["outcome"] not in OUTCOMES:
                raise Refused(f"{where}: unknown outcome {nxt['outcome']!r}")
            when = parse_time(nxt["ts"], f"{where}: ts")
            body = [nxt["credential_id"], nxt["record_hash"], nxt["outcome"]]
            if "reason" in nxt:
                if not isinstance(nxt["reason"], str) or not _REASON.match(nxt["reason"]):
                    raise Refused(f"{where}: reason is not a code")
                prefix, body = OUTCOME_SIG_V2, body + [nxt["reason"]]
            else:
                prefix = OUTCOME_SIG_V1
            body.append(six_digit_time(when))
            self._check_sig(kid, prefix + "\n".join(body).encode("utf-8"), nxt["sig"], where)
            self._limits(kid, rec["seq"], when, where)
            if nxt["outcome"] == "unknown":
                unknown.append((rec["seq"], nxt))
        if index != len(parsed):
            raise Refused(
                f"outcomes.jsonl line {index + 1}: belongs to no record of the segment, in order"
            )
        for credential in missing:
            self.warnings.append({"kind": "outcome_missing", "detail": credential})
        return unknown

    # -- resolutions (version 4) --------------------------------------------
    @staticmethod
    def _resolution_form(res, where):
        def bad(reason):
            raise Refused(f"{where}: {reason}")

        if not _REASON.match(res["reason"]):
            bad("the reason is not a code")
        if not is_hash(res["outcome_ref"]):
            bad("outcome_ref is not a SHA-256")
        digest = res.get("evidence_digest")
        if digest is not None and not is_hash(digest):
            bad("evidence_digest is not a SHA-256")
        resolved, approved = res.get("resolved_by"), res.get("approved_by")
        for who in (resolved, approved):
            if who is not None and (
                    not isinstance(who, str) or not 1 <= len(who.encode("utf-8")) <= 128
                    or any(ord(c) < 32 or 127 <= ord(c) < 160 for c in who)):
                bad("a principal must be 1 to 128 printable characters")
        source, state = res["source"], res["state"]
        if source == "reconciler":
            if state != "ambiguous" or digest is not None or resolved is not None \
                    or approved is not None:
                bad("the reconciler only says ambiguous, with no evidence or principals")
        elif source == "provider_status":
            if digest is None or resolved is not None or approved is not None:
                bad("a provider status carries a digest and no principals")
        elif source == "operator_attested":
            if resolved is None or digest is None:
                bad("an attestation names the person and carries a digest")
            two = state == "confirmed_not_delivered"
            if two and (approved is None or approved == resolved):
                bad("attesting not delivered needs a second, different person")
            if not two and approved is not None:
                bad("this attestation needs one person, not two")
        else:
            if state not in CONFIRMED:
                bad("a conflict is closed by a confirmed state")
            if resolved is None or approved is None or approved == resolved or digest is None:
                bad("a conflict resolution needs two different people and a digest")

    def resolutions(self, lines, unknown, manifest):
        """Checks resolutions.jsonl; returns {credential: [rows]}."""
        by_cred = {entry["credential_id"]: (seq, entry) for seq, entry in unknown}
        found, seen = {}, set()
        for number, raw in enumerate(lines, 1):
            res = _parse_line(raw, RESOLUTIONS, number)
            where = f"{RESOLUTIONS} line {number}"
            _members(res, ["tenant_id", "credential_id", "outcome_ref", "state", "source",
                           "reason", "ts", "key_id", "sig"],
                     ["evidence_digest", "resolved_by", "approved_by"], where)
            for name in ("tenant_id", "credential_id", "outcome_ref", "reason", "key_id", "sig"):
                _str(res[name], f"{where}: {name}")
            if res["tenant_id"] != manifest["tenant_id"]:
                raise Refused(f"{where}: belongs to another tenant")
            target = by_cred.get(res["credential_id"])
            if target is None:
                raise Refused(f"{where}: refers to no unknown outcome of this bundle")
            seq, outcome = target
            if hashlib.sha256(outcome["sig"].encode("ascii")).hexdigest() != res["outcome_ref"]:
                raise Refused(f"{where}: it refers to another outcome row")
            if res["state"] not in RESOLUTION_STATES or res["source"] not in RESOLUTION_SOURCES:
                raise Refused(f"{where}: unknown state or source")
            for name in ("evidence_digest", "resolved_by", "approved_by"):
                if name in res:
                    _str(res[name], f"{where}: {name}")
            self._resolution_form(res, where)
            kid = res["key_id"]
            if not self.dev and kid.startswith("dev-"):
                raise Refused(f"{where}: signed with a development key")
            when = parse_time(res["ts"], f"{where}: ts")
            none = lambda v: "none" if v is None else "some:" + v  # noqa: E731
            body = "\n".join([
                res["tenant_id"], res["credential_id"], res["outcome_ref"], res["state"],
                res["source"], res["reason"], none(res.get("evidence_digest")),
                none(res.get("resolved_by")), none(res.get("approved_by")),
                six_digit_time(when)])
            self._check_sig(kid, RESOLUTION_SIG + body.encode("utf-8"), res["sig"], where)
            self._limits(kid, seq, when, where)
            if when < parse_time(outcome["ts"], "outcome ts"):
                raise Refused(f"{where}: is dated before the outcome it resolves")
            key = (res["credential_id"], res["source"], res["state"])
            if key in seen:
                raise Refused(f"{where}: repeats an earlier resolution")
            seen.add(key)
            found.setdefault(res["credential_id"], []).append(res)
        return found

    @staticmethod
    def _governing(rows):
        closing = {r["state"] for r in rows
                   if r["source"] == "conflict_resolution" and r["state"] in CONFIRMED}
        if len(closing) == 1:
            return "resolved", next(iter(closing)), "conflict_resolution"
        if len(closing) > 1:
            return "conflicted", None, None
        states = {r["state"] for r in rows if r["state"] in CONFIRMED}
        if not states:
            return "unknown", None, None
        if len(states) > 1:
            return "conflicted", None, None
        state = next(iter(states))
        by_provider = any(r["state"] == state and r["source"] == "provider_status" for r in rows)
        return "resolved", state, "provider_status" if by_provider else "operator_attested"

    def settle(self, unknown, found):
        for _seq, outcome in unknown:
            cred = outcome["credential_id"]
            kind, state, source = self._governing(found.get(cred, []))
            if kind == "unknown":
                self.warnings.append({"kind": "outcome_unknown", "detail": cred})
            elif kind == "conflicted":
                self.warnings.append({"kind": "outcome_conflicted", "detail": cred})

    # -- checkpoints -----------------------------------------------------------
    def checkpoint(self, obj, manifest, where):
        _members(obj, ["kind", "version", "tenant_id", "partition_id", "chain", "seq", "head_hash",
                       "prev_checkpoint_hash", "key_id", "time_sync", "ts", "hash", "sig"],
                 what=where)
        if obj["kind"] != "evidence_checkpoint" or obj["version"] != 1:
            raise Refused(f"{where}: not a version 1 checkpoint")
        if (obj["tenant_id"], obj["partition_id"], obj["chain"]) != (
                manifest["tenant_id"], manifest["partition_id"], manifest["chain"]):
            raise Refused(f"{where}: belongs to another chain")
        _int(obj["seq"], "seq", 1)
        for member in ("head_hash", "prev_checkpoint_hash", "hash"):
            if not is_hash(obj[member]):
                raise Refused(f"{where}: {member} is not 64 lowercase hex")
        _members(obj["time_sync"], ["status", "max_error_ms"], what=f"{where}: time_sync")
        kid = _str(obj["key_id"], f"{where}: key_id")
        if not self.dev and (kid.startswith("dev-") or obj["time_sync"]["status"] == "dev_fixed"):
            raise Refused(f"{where}: development evidence outside a development stack")
        payload = {k: v for k, v in obj.items() if k not in ("hash", "sig")}
        if hashlib.sha256(CHECKPOINT_PREFIX + jcs(payload)).hexdigest() != obj["hash"]:
            raise Refused(f"{where}: hash does not match its content")
        self._check_sig(kid, _signed(CHECKPOINT_SIG, obj["hash"]), obj["sig"], where)
        when = parse_time(obj["ts"], f"{where}: ts")
        return when

    def checkpoints(self, lines, records, manifest, kept):
        seg = manifest["segment"]
        by_seq = {r["seq"]: r["hash"] for r in records}
        previous, previous_ts, covered = None, None, seg["after_seq"]
        have = {}
        for number, raw in enumerate(lines, 1):
            where = f"checkpoints.jsonl line {number}"
            obj = _parse_line(raw, "checkpoints.jsonl", number)
            when = self.checkpoint(obj, manifest, where)
            self._limits(obj["key_id"], obj["seq"], when, where)
            if previous is not None:
                if obj["seq"] <= previous["seq"]:
                    raise Refused(f"{where}: seq does not increase")
                if obj["prev_checkpoint_hash"] != previous["hash"]:
                    raise Refused(f"{where}: does not follow the checkpoint before it")
                if when < previous_ts:
                    self.warnings.append({"kind": "clock_stepped_back", "detail": where})
            elif seg["after_seq"] == 0 and obj["prev_checkpoint_hash"] != GENESIS:
                raise Refused(f"{where}: the first checkpoint must follow genesis")
            self._compare(obj, by_seq, seg, where)
            if seg["after_seq"] < obj["seq"] <= seg["last_seq"]:
                covered = max(covered, obj["seq"])
            have[obj["seq"]] = obj["head_hash"]
            previous, previous_ts = obj, when
        return have, covered

    def _compare(self, obj, by_seq, seg, where):
        seq = obj["seq"]
        if seq > seg["last_seq"]:
            raise Refused(f"{where}: covers record {seq}, but the records end at {seg['last_seq']}: "
                          "records were removed")
        if seq == seg["after_seq"]:
            if obj["head_hash"] != seg["after_hash"]:
                raise Refused(f"{where}: its head hash differs from the segment's start")
        elif seq > seg["after_seq"]:
            if obj["head_hash"] != by_seq[seq]:
                raise Refused(f"{where}: its head hash differs from record {seq}: the chain was rewritten")


def verify_bundle(directory, keys_path, kept_path=None, dev=False, now=None):
    """Returns a report dict; raises Refused if the bundle does not verify."""
    real = os.path.realpath(directory)
    if os.path.commonpath([real, os.path.realpath(keys_path)]) == real:
        raise Refused("the keys file must not be inside the bundle")
    names = sorted(os.listdir(directory))
    # The manifest says which files belong: a resolutions file from version 4.
    manifest_path = os.path.join(directory, "manifest.json")
    if not os.path.exists(manifest_path):
        raise Refused("manifest.json is missing")
    with open(manifest_path, "rb") as handle:
        head = handle.read()
    head = head[:-1] if head.endswith(b"\n") else head
    version = _parse_line(head, "manifest.json", 1)
    version = version.get("version") if isinstance(version, dict) else None
    files = FILES + ([RESOLUTIONS] if isinstance(version, int) and version >= RESOLUTIONS_SINCE else [])
    if names != sorted(files):
        raise Refused(f"the bundle must hold exactly {files}, not {names}")
    data = {}
    for name in files:
        path = os.path.join(directory, name)
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise Refused(f"{name} is not a regular file")
        with open(path, "rb") as handle:
            data[name] = handle.read()
    keys = load_keys(keys_path)
    v = Verifier(keys, dev=dev, now=now)

    text = data["manifest.json"]
    if text.endswith(b"\n"):
        text = text[:-1]
    manifest = _parse_line(text, "manifest.json", 1)
    v.manifest(manifest)

    rec_lines = _lines(data["records.jsonl"], "records.jsonl")
    out_lines = _lines(data["outcomes.jsonl"], "outcomes.jsonl")
    cp_lines = _lines(data["checkpoints.jsonl"], "checkpoints.jsonl")
    res_lines = []
    streams = [("records", rec_lines), ("outcomes", out_lines), ("checkpoints", cp_lines)]
    if RESOLUTIONS in data:
        res_lines = _lines(data[RESOLUTIONS], RESOLUTIONS)
        streams.append(("resolutions", res_lines))
    for name, lines in streams:
        entry = manifest["files"][name]
        if hashlib.sha256(data[f"{name}.jsonl"]).hexdigest() != entry["sha256"]:
            raise Refused(f"{name}.jsonl: its digest does not match the manifest")
        if len(lines) != entry["count"]:
            raise Refused(f"{name}.jsonl: {len(lines)} lines, the manifest says {entry['count']}")

    kept = None
    if kept_path is not None:
        with open(kept_path, "r", encoding="utf-8") as handle:
            rows = [row for row in handle.read().split("\n") if row.strip()]
        if not rows:
            raise Refused("the kept checkpoint file is empty")
        kept = loads(rows[-1])
        kept_when = v.checkpoint(kept, manifest, "kept checkpoint")
        v.kept_seq = kept["seq"]
        v._limits(kept["key_id"], kept["seq"], kept_when, "kept checkpoint")

    exported = parse_time(manifest["exported_at"], "exported_at")
    if "key_id" in manifest:
        v._limits(manifest["key_id"], manifest["segment"]["last_seq"], exported, "manifest")
    records = v.records(rec_lines, manifest)
    unknown = v.outcomes(out_lines, records, manifest)
    v.settle(unknown, v.resolutions(res_lines, unknown, manifest))
    have, covered = v.checkpoints(cp_lines, records, manifest, kept)

    seg = manifest["segment"]
    if seg["after_seq"] != 0:
        vouched = have.get(seg["after_seq"]) == seg["after_hash"] or (
            kept is not None and kept["seq"] == seg["after_seq"] and kept["head_hash"] == seg["after_hash"])
        if not vouched:
            raise Refused(f"the segment follows record {seg['after_seq']}, and no checkpoint vouches for it")
    if kept is not None:
        seq = kept["seq"]
        if seq > seg["last_seq"]:
            raise Refused("the kept checkpoint is newer than the records: records were removed")
        if seq == seg["after_seq"]:
            if kept["head_hash"] != seg["after_hash"]:
                raise Refused("the kept checkpoint differs from the segment's start")
        elif seq > seg["after_seq"]:
            if kept["head_hash"] != {r["seq"]: r["hash"] for r in records}[seq]:
                raise Refused("the kept checkpoint differs from the chain: it was rewritten")
            if have and seq <= max(have) and have.get(seq) != kept["head_hash"]:
                raise Refused("the kept checkpoint is not among the bundle's checkpoints")
    uncovered = seg["last_seq"] - covered
    if uncovered > 0:
        v.warnings.append({"kind": "uncovered_records", "detail": str(uncovered)})
    if kept is None:
        v.warnings.append({"kind": "no_kept_checkpoint", "detail": "no checkpoint was kept off-host"})
    return {
        "result": "verified" if not v.warnings else "verified_with_warnings",
        "version": manifest["version"],
        "records": len(records),
        "outcomes": len(out_lines),
        "resolutions": len(res_lines),
        "checkpoints": len(cp_lines),
        "last_seq": seg["last_seq"],
        "warnings": v.warnings,
    }


# --------------------------------------------------------------------------
# The credential (credential-format.md)
# --------------------------------------------------------------------------

def concat_kdf(z, algorithm_id, key_bits):
    def field(raw):
        return len(raw).to_bytes(4, "big") + raw

    other = field(algorithm_id.encode("ascii")) + field(b"") + field(b"") + key_bits.to_bytes(4, "big")
    return hashlib.sha256((1).to_bytes(4, "big") + z + other).digest()[: key_bits // 8]


def open_credential(token, provider_secret, provider_kid, signing_keys, audience, now):
    """Decrypts and verifies a credential; returns its claims (spec section 4)."""
    if len(token) > 32 * 1024:
        raise Refused("the token is too long")
    parts = token.split(".")
    if len(parts) != 5 or parts[1] != "":
        raise Refused("a JWE of five parts with an empty encrypted key")
    h64, _, iv64, ct64, tag64 = parts
    header_raw = b64url_decode(h64, "header")
    header = loads(header_raw.decode("utf-8"))
    _members(header, ["alg", "enc", "epk", "kid", "typ", "cty"], what="JWE header")
    if jcs(header) != header_raw:
        raise Refused("the JWE header is not canonical")
    if (header["alg"], header["enc"]) != ("ECDH-ES", "A256GCM"):
        raise Refused("unsupported alg or enc")
    if (header["typ"], header["cty"]) != ("kavach-credential+jwe", "kavach-credential+jws"):
        raise Refused("unexpected typ or cty")
    if header["kid"] != provider_kid:
        raise Refused("the JWE is for another recipient key")
    epk = header["epk"]
    _members(epk, ["kty", "crv", "x"], what="epk")
    if epk["kty"] != "OKP" or epk["crv"] != "X25519":
        raise Refused("epk must be an X25519 OKP key")
    shared = x25519(provider_secret, b64url_decode(epk["x"], "epk"))
    if shared == bytes(32):
        raise Refused("epk is a low-order point")
    cek = concat_kdf(shared, "A256GCM", 256)
    plaintext = aes256_gcm_open(cek, b64url_decode(iv64, "iv"), h64.encode("ascii"),
                                b64url_decode(ct64, "ciphertext"), b64url_decode(tag64, "tag"))
    jws = plaintext.decode("utf-8")
    if len(jws) > 16 * 1024:
        raise Refused("the inner JWS is too long")
    p = jws.split(".")
    if len(p) != 3:
        raise Refused("the inner JWS must have three parts")
    jh_raw, jp_raw = b64url_decode(p[0], "jws header"), b64url_decode(p[1], "jws payload")
    jh = loads(jh_raw.decode("utf-8"))
    _members(jh, ["alg", "kid", "typ"], what="JWS header")
    if jh["alg"] != "EdDSA" or jh["typ"] != "kavach-credential+jws":
        raise Refused("unsupported inner alg or typ")
    if jcs(jh) != jh_raw:
        raise Refused("the JWS header is not canonical")
    key = signing_keys.get(jh["kid"])
    if key is None:
        raise Refused("the credential key is not trusted")
    if not ed25519_verify(key, (p[0] + "." + p[1]).encode("ascii"), b64url_decode(p[2], "signature")):
        raise Refused("the credential signature does not verify")
    claims = loads(jp_raw.decode("utf-8"))
    if jcs(claims) != jp_raw:
        raise Refused("the claims are not canonical")
    _members(claims, ["iss", "tenant", "agent", "mandate_id", "record_id", "jti", "aud", "action",
                      "req", "iat", "exp"], ["send_by"], "claims")
    _members(claims["req"], ["channel", "destination", "template_id"], what="req")
    if claims["aud"] != audience:
        raise Refused("the credential is for another audience")
    iat, exp = _int(claims["iat"], "iat"), _int(claims["exp"], "exp")
    if exp - iat > 15 or exp <= iat:
        raise Refused("the credential lifetime is out of bounds")
    if iat > now + 5:
        raise Refused("the credential is issued in the future")
    if now >= exp:
        raise Refused("the credential has expired")
    if "send_by" in claims:
        send_by = _int(claims["send_by"], "send_by")
        if now >= send_by or exp > send_by:
            raise Refused("the credential is past send_by")
    return claims


# --------------------------------------------------------------------------
# Mandates and system-of-record events (mandate-and-sor-event.md)
# --------------------------------------------------------------------------

TYP_MANDATE = "kavach-mandate+jws"
TYP_SOR_EVENT = "kavach-sor-event+jws"
MAX_TOKEN = 16 * 1024
MAX_DEPTH = 4
ALLOWED_CHANNELS = {"sms", "voice", "whatsapp"}
CONTACT_ACTIONS = {"send_reminder", "place_call"}
MAX_TTL = 30 * 24 * 3600
EVENT_ORDER = ["event_id", "tenant_id", "system", "event_type", "record_ref", "subject_ref",
               "principal", "consent_refs", "assigned_agent", "occurred_at", "nonce"]
_SHORT_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(\d{3}|\d{6}|\d{9}))?Z$")
_CAP_PART = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


def shortest_time(text, what):
    """A time written in the shortest exact form (spec section 1, Times)."""
    m = _SHORT_TIME.match(text) if isinstance(text, str) else None
    if not m:
        raise Refused(f"{what}: {text!r} is not RFC 3339 UTC in the shortest form", "canonical-payload")
    frac = m.group(1)
    if frac is not None and len(frac) > 3 and frac.endswith("000"):
        raise Refused(f"{what}: {text!r} has digits that are not needed", "canonical-payload")
    if frac is not None and frac == "0" * len(frac):
        raise Refused(f"{what}: {text!r} has a zero fraction", "canonical-payload")
    return parse_time(text, what)


def is_capability_ref(text):
    if not isinstance(text, str) or not text.startswith("ref:"):
        return False
    parts = text[4:].split(":", 1)
    return len(parts) == 2 and all(_CAP_PART.match(p) for p in parts)


def verify_jws(token, typ, keys):
    """Spec section 1. keys: kid -> 32-byte public key. Returns (kid, payload)."""
    if len(token) > MAX_TOKEN:
        raise Refused("the token is too long")
    parts = token.split(".")
    if len(parts) != 3:
        raise Refused("a token has three parts", "parts")
    header_raw = b64url_decode(parts[0], "header")
    header = loads(header_raw.decode("utf-8"))
    _members(header, ["alg", "kid", "typ"], what="header")
    if header["alg"] != "EdDSA":
        raise Refused("alg must be EdDSA", "alg")
    if header["typ"] != typ:
        raise Refused(f"typ must be {typ}", "typ")
    if jcs(header) != header_raw:
        raise Refused("the header is not canonical", "canonical-header")
    key = keys.get(header["kid"])
    if key is None:
        raise Refused(f"key {header['kid']!r} is not known", "key")
    sig = b64url_decode(parts[2], "signature")
    if not ed25519_verify(key, (parts[0] + "." + parts[1]).encode("ascii"), sig):
        raise Refused("the signature does not verify", "signature")
    payload_raw = b64url_decode(parts[1], "payload")
    try:
        payload = loads(payload_raw.decode("utf-8"))
    except UnicodeDecodeError:
        raise Refused("the payload is not UTF-8") from None
    if jcs(payload) != payload_raw:
        raise Refused("the payload is not canonical", "canonical-payload")
    return header["kid"], payload


def _string_set(value, what):
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise Refused(f"{what} is not an array of strings")
    if value != sorted(set(value), key=lambda v: v.encode("utf-16-be")):
        raise Refused(f"{what} is not sorted without repeats", "canonical-payload")
    return value


def check_event(payload):
    _members(payload, EVENT_ORDER, what="event")
    for name in EVENT_ORDER:
        if name not in ("consent_refs",):
            _str(payload[name], f"event {name}")
    _string_set(payload["consent_refs"], "consent_refs")
    if not is_capability_ref(payload["subject_ref"]):
        raise Refused("subject_ref is not a capability reference")
    return shortest_time(payload["occurred_at"], "occurred_at")


def event_digest(event):
    """The event's digest (section 5): SHA-256 of its RFC 8785 bytes, tagged."""
    return EVENT_DIGEST_PREFIX + hashlib.sha256(jcs(event)).hexdigest()


def legacy_content_sha256(event):
    """The digest written before event_digest: compact JSON in declaration order.
    Only to recognise records and rows of that form."""
    parts = []
    for name in EVENT_ORDER:
        value = event[name]
        if name == "consent_refs":
            text = "[" + ",".join(_jstr(v) for v in value) + "]"
        else:
            text = _jstr(value)
        parts.append(_jstr(name) + ":" + text)
    return hashlib.sha256(("{" + ",".join(parts) + "}").encode("utf-8")).hexdigest()


MANDATE_MEMBERS = ["mv", "id", "tenant_id", "issuer", "source", "principal", "holder",
                   "subject_ref", "purpose", "consent_refs", "actions", "data_fields", "channels",
                   "window", "ceilings", "delegation", "parent_id", "depth", "nbf", "exp", "nonce"]


def _window(value):
    if value is None:
        return None
    _members(value, ["tz", "from_min", "to_min", "max_per_day"], what="window")
    if value["tz"] != "Asia/Kolkata":
        raise Refused("window tz must be Asia/Kolkata")
    for name in ("from_min", "to_min", "max_per_day"):
        _int(value[name], f"window {name}", 0)
    if not (480 <= value["from_min"] < value["to_min"] <= 1140 and value["max_per_day"] > 0):
        raise Refused("the contact window is outside the 08:00-19:00 floor")
    return value


def check_mandate(m):
    """The member and form rules of section 3. Returns (nbf, exp)."""
    _members(m, MANDATE_MEMBERS, what="mandate")
    if _int(m["mv"], "mv") != 1:
        raise Refused("unknown mandate version")
    for name in ("id", "tenant_id", "issuer", "principal", "holder", "subject_ref", "purpose",
                 "nonce"):
        _str(m[name], f"mandate {name}")
    _members(m["source"], ["system", "record_ref", "event_id"], what="source")
    if not is_capability_ref(m["subject_ref"]):
        raise Refused("subject_ref is not a capability reference")
    for name in ("consent_refs", "actions", "data_fields", "channels"):
        _string_set(m[name], name)
    if not set(m["channels"]) <= ALLOWED_CHANNELS:
        raise Refused("unknown channel")
    window = _window(m["window"])
    if window is None and set(m["actions"]) & CONTACT_ACTIONS:
        raise Refused("contact actions without a contact window")
    if not isinstance(m["ceilings"], dict):
        raise Refused("ceilings is not an object")
    for key, value in m["ceilings"].items():
        _int(value, f"ceiling {key}")
        if not 0 <= value <= (10_000 if key.endswith("_bps") else MAX_SAFE):
            raise Refused(f"ceiling {key} is out of range")
    _members(m["delegation"], ["max_depth", "allowed_agents"], what="delegation")
    if not 0 <= _int(m["delegation"]["max_depth"], "max_depth") <= MAX_DEPTH:
        raise Refused("delegation max_depth is above the limit")
    _string_set(m["delegation"]["allowed_agents"], "allowed_agents")
    depth = _int(m["depth"], "depth", 0)
    if depth > MAX_DEPTH or (depth == 0) != (m["parent_id"] is None):
        raise Refused("depth and parent_id disagree, or depth is above the limit")
    if m["parent_id"] is not None:
        _str(m["parent_id"], "parent_id")
    nbf, exp = shortest_time(m["nbf"], "nbf"), shortest_time(m["exp"], "exp")
    life = (exp - nbf).total_seconds()
    if not 1 <= life <= MAX_TTL:
        raise Refused("lifetime is not within 1 second to 30 days")
    return nbf, exp


def check_delegation(child, parent):
    """Section 3, Delegation: raises Refused unless child only narrows parent."""
    same = ["tenant_id", "subject_ref", "purpose", "consent_refs", "source", "issuer"]
    if any(child[k] != parent[k] for k in same):
        raise Refused("a child must keep tenant, subject, purpose, consents, source and issuer")
    for name in ("actions", "data_fields", "channels"):
        if not set(child[name]) <= set(parent[name]):
            raise Refused(f"child {name} are not within the parent's")
    cw, pw = child["window"], parent["window"]
    if pw is not None:
        if cw is None or not (cw["from_min"] >= pw["from_min"] and cw["to_min"] <= pw["to_min"]
                              and cw["max_per_day"] <= pw["max_per_day"]):
            raise Refused("the child window is not within the parent's")
    for key, value in child["ceilings"].items():
        if key not in parent["ceilings"] or value > parent["ceilings"][key]:
            raise Refused(f"child ceiling {key} exceeds the parent's")
    if shortest_time(child["exp"], "exp") > shortest_time(parent["exp"], "exp"):
        raise Refused("the child outlives its parent")
    if shortest_time(child["nbf"], "nbf") < shortest_time(parent["nbf"], "nbf"):
        raise Refused("the child starts before its parent")
    pd = parent["delegation"]
    if (child["depth"] != parent["depth"] + 1 or child["depth"] > pd["max_depth"]
            or child["parent_id"] != parent["id"] or child["holder"] not in pd["allowed_agents"]
            or child["delegation"]["max_depth"] > pd["max_depth"]
            or not set(child["delegation"]["allowed_agents"]) <= set(pd["allowed_agents"])):
        raise Refused("the child is not a valid delegation of the parent")


# An issuing event dated further ahead than this is refused (specification
# section 2, Freshness).
ISSUING_FUTURE_BOUND = 60


def run_mandate(path):
    with open(path, "r", encoding="utf-8") as handle:
        vector = loads(handle.read())
    mkeys = {vector["mandate_key"]["kid"]: _jwk_bytes(vector["mandate_key"], "x")}
    sor_keys, sor_binding = {}, {}
    for issuer in vector["sor_issuers"]:
        sor_keys[issuer["key"]["kid"]] = _jwk_bytes(issuer["key"], "x")
        sor_binding[issuer["key"]["kid"]] = (issuer["tenant_id"], issuer["system"])
    freshness = vector["freshness_seconds"]
    decoded = {}
    for item in vector["mandates"]:
        _, payload = verify_jws(item["token"], TYP_MANDATE, mkeys)
        check_mandate(payload)
        if payload != item["payload"]:
            raise Refused(f"mandate {item['name']}: payload differs from the vector's")
        decoded[item["name"]] = payload
    for item in vector["mandates"]:
        if "parent" in item:
            check_delegation(decoded[item["name"]], decoded[item["parent"]])
    checks = []
    for item in vector["events"]:
        kid, payload = verify_jws(item["token"], TYP_SOR_EVENT, sor_keys)
        occurred = check_event(payload)
        if payload != item["payload"]:
            raise Refused(f"event {item['name']}: payload differs from the vector's")
        if sor_binding[kid] != (payload["tenant_id"], payload["system"]):
            raise Refused(f"event {item['name']}: key not registered for its tenant and system")
        if event_digest(payload) != item["event_digest"]:
            raise Refused(f"event {item['name']}: event_digest differs")
        if legacy_content_sha256(payload) != item["legacy_content_sha256"]:
            raise Refused(f"event {item['name']}: legacy_content_sha256 differs")
        at = datetime.fromtimestamp(item["fresh_at"], timezone.utc)
        # `age` is how long ago the event occurred at the reference time
        # (negative: in the future). An issuing event more than `freshness`
        # old or ahead is refused; a revoking event has no bound either way.
        revoking = payload["event_type"] in ("loan.paid", "loan.disputed")
        # An issuing event may be at most ISSUING_FUTURE_BOUND ahead (T1) and
        # `freshness` old.
        for delta, issuing_fresh in ((0, True), (freshness, True), (-ISSUING_FUTURE_BOUND, True),
                                     (freshness + 1, False), (-ISSUING_FUTURE_BOUND - 1, False)):
            age = (at + timedelta(seconds=delta) - occurred).total_seconds()
            fresh = True if revoking else -ISSUING_FUTURE_BOUND <= age <= freshness
            expected = issuing_fresh or revoking
            if fresh != expected:
                raise Refused(f"event {item['name']}: freshness is wrong at {delta:+d}s")
        checks.append(item["name"])
    refused = []
    every = dict(mkeys, **sor_keys)
    for case in vector["refused"]:
        try:
            _, payload = verify_jws(case["token"], case["typ"], every)
            if case["typ"] == TYP_MANDATE:
                check_mandate(payload)
            else:
                check_event(payload)
        except Refused as error:
            if error.rule != case["rule"]:
                raise Refused(
                    f"{case['name']} was refused for {error.rule!r} ({error}), "
                    f"not for its own rule {case['rule']!r}") from None
            refused.append(case["name"])
            continue
        except UnicodeDecodeError:
            refused.append(case["name"])
            continue
        raise Refused(f"{case['name']} was accepted")
    # Genuinely signed, but by a key registered for another tenant or system.
    binding = []
    for case in vector["binding_refused"]:
        kid, payload = verify_jws(case["token"], TYP_SOR_EVENT, sor_keys)
        check_event(payload)
        if sor_binding[kid] == (payload["tenant_id"], payload["system"]):
            raise Refused(f"{case['name']} is inside the issuer binding")
        binding.append(case["name"])
    return {"result": "verified", "mandates": sorted(decoded), "events": checks, "refused": refused,
            "binding_refused": binding}


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def _jwk_bytes(jwk, member):
    return b64url_decode(jwk[member], f"jwk {member}")


def run_credential(path, now):
    with open(path, "r", encoding="utf-8") as handle:
        vector = loads(handle.read())
    secret = _jwk_bytes(vector["provider_jwk"], "d")
    kid = vector["provider_jwk"]["kid"]
    keys = {vector["credential_signing_jwk"]["kid"]: _jwk_bytes(vector["credential_signing_jwk"], "x")}
    at = vector["verify_at"] if now is None else now
    claims = open_credential(vector["token"], secret, kid, keys, vector["audience"], at)
    if claims != vector["claims"]:
        raise Refused("the claims differ from the vector's")
    if hashlib.sha256(jcs(claims)).hexdigest() != vector["claims_sha256"]:
        raise Refused("claims_sha256 differs")
    checks = []

    def must_refuse(label, token=None, **kw):
        args = dict(token=token or vector["token"], provider_secret=secret, provider_kid=kid,
                    signing_keys=keys, audience=vector["audience"], now=at)
        args.update(kw)
        try:
            open_credential(**args)
        except Refused:
            checks.append(label)
            return
        raise Refused(f"{label}: was not refused")

    parts = vector["token"].split(".")
    tag = bytearray(b64url_decode(parts[4]))
    tag[0] ^= 1
    must_refuse("a flipped tag bit", token=".".join(parts[:4] + [b64url_encode(bytes(tag))]))
    must_refuse("expiry", now=at + 15)
    must_refuse("another audience", audience="another-provider")
    must_refuse("another recipient key", provider_kid="another-key")
    return {"result": "verified", "claims_sha256": vector["claims_sha256"], "refused": checks}


def run_jcs(path):
    with open(path, "r", encoding="utf-8") as handle:
        vector = json.load(handle)
    for case in vector["cases"]:
        got = jcs(loads(case["input"])).decode("utf-8")
        if got != case["canonical"]:
            raise Refused(f"jcs case {case['name']}: {got!r} != {case['canonical']!r}")
    for case in vector["refused"]:
        try:
            jcs(loads(case["input"]))
        except Refused:
            continue
        raise Refused(f"jcs case {case['name']} should have been refused")
    return {"result": "verified", "cases": len(vector["cases"]), "refused": len(vector["refused"])}


def run_checkpoints(path):
    with open(path, "r", encoding="utf-8") as handle:
        vector = json.load(handle)
    public = bytes.fromhex(vector["public_key"]["public_key"])
    prefix, sig_prefix = vector["hash_prefix"].encode(), vector["signing_prefix"].encode()
    done = 0
    for item in vector["checkpoints"]:
        obj = item["checkpoint"]
        payload = {k: v for k, v in obj.items() if k not in ("hash", "sig")}
        canonical = jcs(payload)
        if canonical.decode("utf-8") != item["canonical_payload"]:
            raise Refused("the canonical payload differs from the vector's")
        if hashlib.sha256(prefix + canonical).hexdigest() != obj["hash"]:
            raise Refused("checkpoint hash differs")
        if not ed25519_verify(public, sig_prefix + obj["hash"].encode("ascii"), bytes.fromhex(obj["sig"])):
            raise Refused("checkpoint signature does not verify")
        if obj["head_hash"] not in vector["record_hashes"]:
            raise Refused("head_hash is not one of the vector's record hashes")
        done += 1
    return {"result": "verified", "checkpoints": done}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("bundle")
    b.add_argument("directory")
    b.add_argument("--keys", required=True)
    b.add_argument("--expect-checkpoint")
    b.add_argument("--now", help="RFC 3339 UTC; the reference time for expired credentials")
    b.add_argument("--dev", action="store_true")
    b.add_argument("--allow-warnings", action="store_true")
    c = sub.add_parser("credential")
    c.add_argument("vector")
    c.add_argument("--now", type=int)
    for name in ("jcs", "checkpoints", "mandate"):
        sub.add_parser(name).add_argument("vector")
    args = parser.parse_args(argv)
    try:
        if args.command == "bundle":
            now = parse_time(args.now, "--now") if args.now else None
            report = verify_bundle(args.directory, args.keys, args.expect_checkpoint, args.dev, now)
        elif args.command == "credential":
            report = run_credential(args.vector, args.now)
        elif args.command == "jcs":
            report = run_jcs(args.vector)
        elif args.command == "mandate":
            report = run_mandate(args.vector)
        else:
            report = run_checkpoints(args.vector)
    except (Refused, OSError, KeyError, ValueError) as error:
        print(json.dumps({"result": "fail", "reason": str(error)}))
        return 1
    print(json.dumps(report, indent=2))
    if report["result"] == "verified_with_warnings" and not getattr(args, "allow_warnings", False):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
