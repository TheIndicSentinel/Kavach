"""Conformance tests: the published vectors must verify, and every mutation must not.

Run from the repository root:  python3 -I -m unittest discover -s conformance -v
"""

import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kavach_verify as kv  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUNDLES = os.path.join(ROOT, "crates/kavach-evidence-cli/tests/vectors")
PORTS = os.path.join(ROOT, "crates/kavach-ports/tests/vectors")
MANDATE = os.path.join(ROOT, "crates/kavach-mandate/tests/vectors/mandate-v1.json")
CRED = os.path.join(ROOT, "crates/kavach-credential/tests/vectors/credential-v1.json")
NOW = kv.parse_time("2026-10-02T07:00:00Z")


def kinds(report):
    return sorted(w["kind"] for w in report["warnings"])


class Vectors(unittest.TestCase):
    def test_jcs(self):
        self.assertEqual(kv.run_jcs(os.path.join(PORTS, "jcs-v1.json"))["result"], "verified")

    def test_checkpoints(self):
        r = kv.run_checkpoints(os.path.join(PORTS, "checkpoint-v1.json"))
        self.assertEqual(r["checkpoints"], 2)

    def test_credential(self):
        self.assertEqual(kv.run_credential(CRED, None)["result"], "verified")

    def test_bundle_v1(self):
        r = kv.verify_bundle(f"{BUNDLES}/bundle-v1", f"{BUNDLES}/bundle-v1.keys.json", now=NOW)
        self.assertEqual(kinds(r), ["no_kept_checkpoint", "outcome_missing", "outcome_unknown",
                                    "uncovered_records"])

    def test_bundle_v2(self):
        r = kv.verify_bundle(f"{BUNDLES}/bundle-v2", f"{BUNDLES}/bundle-v2.keys.json", now=NOW)
        self.assertEqual(kinds(r), ["no_kept_checkpoint", "outcome_missing", "outcome_unknown"])
        self.assertEqual(r["records"], 5)


class Mutations(unittest.TestCase):
    """Each case edits a copy of bundle-v2 and expects a refusal."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.bundle = os.path.join(self.dir, "b")
        shutil.copytree(f"{BUNDLES}/bundle-v2", self.bundle)
        self.keys = f"{BUNDLES}/bundle-v2.keys.json"

    def tearDown(self):
        shutil.rmtree(self.dir)

    def path(self, name):
        return os.path.join(self.bundle, name)

    def rows(self, name):
        with open(self.path(name), encoding="utf-8") as h:
            if name == "manifest.json":
                return [json.load(h)]
            return [json.loads(line) for line in h if line.strip()]

    def write(self, name, rows):
        with open(self.path(name), "w", encoding="utf-8") as h:
            for row in rows:
                h.write(kv.jcs(row).decode() + "\n")

    def refuse(self, fragment):
        with self.assertRaises(kv.Refused) as ctx:
            kv.verify_bundle(self.bundle, self.keys, now=NOW)
        self.assertIn(fragment, str(ctx.exception))

    def reseal(self, rows):
        """Recomputes the chain, the file digests and the manifest hash. Signatures are not
        recomputed (there is no private key), so callers stub signature checks."""
        prev = None
        manifest = self.rows("manifest.json")[0]
        prev = manifest["segment"]["after_hash"]
        for row in rows:
            row["prev_hash"] = prev
            payload = {k: v for k, v in row.items() if k not in ("hash", "sig")}
            row["hash"] = hashlib.sha256(kv.RECORD_PREFIX + prev.encode() + kv.jcs(payload)).hexdigest()
            prev = row["hash"]
        self.write("records.jsonl", rows)
        manifest["segment"]["head_hash"] = prev
        self.seal_manifest(manifest)

    def seal_manifest(self, manifest):
        for name in ("records", "outcomes", "checkpoints"):
            with open(self.path(f"{name}.jsonl"), "rb") as h:
                data = h.read()
            manifest["files"][name] = {"sha256": hashlib.sha256(data).hexdigest(),
                                       "count": data.count(b"\n")}
        manifest.pop("sig", None)
        manifest.pop("key_id", None)
        payload = {k: v for k, v in manifest.items() if k != "hash"}
        manifest["hash"] = hashlib.sha256(kv.MANIFEST_PREFIX + kv.jcs(payload)).hexdigest()
        self.write("manifest.json", [manifest])

    def structural(self):
        """Signature checks pass, so only structure can refuse."""
        return mock.patch.object(kv.Verifier, "_check_sig", lambda *a, **k: None)

    # -- with real signatures: any edit is caught ------------------------
    def test_flipped_byte_in_a_record(self):
        rows = self.rows("records.jsonl")
        rows[1]["payload_note"] = "x"
        self.write("records.jsonl", rows)
        self.refuse("digest does not match")

    def test_manifest_edit(self):
        m = self.rows("manifest.json")[0]
        m["exporter"]["tool"] = "other"
        self.write("manifest.json", [m])
        self.refuse("hash does not match")

    def test_removed_checkpoint_file_line(self):
        rows = self.rows("checkpoints.jsonl")[:-1]
        self.write("checkpoints.jsonl", rows)
        self.refuse("digest does not match")

    def test_extra_file(self):
        open(self.path("notes.txt"), "w").close()
        self.refuse("must hold exactly")

    def test_wrong_keys(self):
        other = os.path.join(self.dir, "empty.keys.json")
        with open(other, "w") as h:
            h.write('{"keys":[]}')
        with self.assertRaises(kv.Refused) as ctx:
            kv.verify_bundle(self.bundle, other, now=NOW)
        self.assertIn("not trusted", str(ctx.exception))

    def test_keys_inside_bundle(self):
        shutil.copy(self.keys, self.path("keys.json"))
        with self.assertRaises(kv.Refused):
            kv.verify_bundle(self.path("."), self.path("keys.json"), now=NOW)

    # -- resealed, signatures stubbed: structure alone must refuse --------
    def test_unknown_record_kind_is_refused_not_skipped(self):
        rows = self.rows("records.jsonl")
        rows[2]["kind"] = "future_kind"
        self.reseal(rows)
        with self.structural():
            self.refuse("registry")

    def test_version_1_bundle_holding_a_revocation(self):
        rows = self.rows("records.jsonl")
        self.assertTrue(any(r["kind"] == "mandate_revocation" for r in rows))
        manifest = self.rows("manifest.json")[0]
        manifest["version"] = 1
        self.seal_manifest(manifest)
        with self.structural():
            self.refuse("registry")

    def test_duplicate_member_name(self):
        with open(self.path("records.jsonl"), encoding="utf-8") as h:
            lines = h.read().split("\n")
        lines[0] = lines[0][:-1] + ',"seq":1}'
        with open(self.path("records.jsonl"), "w", encoding="utf-8") as h:
            h.write("\n".join(lines))
        manifest = self.rows("manifest.json")[0]
        self.seal_manifest(manifest)
        with self.structural():
            self.refuse("duplicate member name")

    def test_removed_record(self):
        rows = self.rows("records.jsonl")
        del rows[2]
        self.reseal(rows)
        with self.structural():
            with self.assertRaises(kv.Refused):
                kv.verify_bundle(self.bundle, self.keys, now=NOW)

    def test_repeated_record(self):
        rows = self.rows("records.jsonl")
        rows.insert(2, copy.deepcopy(rows[1]))
        self.reseal(rows)
        with self.structural():
            with self.assertRaises(kv.Refused):
                kv.verify_bundle(self.bundle, self.keys, now=NOW)

    def test_hash_alg_must_be_v2(self):
        rows = self.rows("records.jsonl")
        rows[0]["hash_alg"] = "v1"
        self.reseal(rows)
        with self.structural():
            self.refuse("hash_alg")

    def test_repeated_outcome(self):
        rows = self.rows("outcomes.jsonl")
        rows.append(copy.deepcopy(rows[-1]))
        self.write("outcomes.jsonl", rows)
        manifest = self.rows("manifest.json")[0]
        self.seal_manifest(manifest)
        with self.structural():
            with self.assertRaises(kv.Refused):
                kv.verify_bundle(self.bundle, self.keys, now=NOW)

    def test_fractional_number_in_a_record(self):
        with open(self.path("records.jsonl"), encoding="utf-8") as h:
            lines = h.read().split("\n")
        lines[0] = lines[0][:-1] + ',"x":1.5}'
        with open(self.path("records.jsonl"), "w", encoding="utf-8") as h:
            h.write("\n".join(lines))
        with self.assertRaises(kv.Refused):
            kv.verify_bundle(self.bundle, self.keys, now=NOW)


class Mandates(unittest.TestCase):
    def setUp(self):
        with open(MANDATE, encoding="utf-8") as h:
            self.v = json.load(h)
        self.root = copy.deepcopy(self.v["mandates"][0]["payload"])
        self.child = copy.deepcopy(self.v["mandates"][1]["payload"])

    def test_vector(self):
        r = kv.run_mandate(MANDATE)
        self.assertEqual(r["events"], ["issuing", "revoking"])
        self.assertEqual(len(r["refused"]), len(self.v["refused"]))

    def test_event_hash_is_not_the_signed_form(self):
        e = self.v["events"][0]
        self.assertNotEqual(e["content_sha256"], e["signed_payload_sha256"])

    def test_form_rules(self):
        kv.check_mandate(self.root)
        edits = {
            "version": {"mv": 2},
            "raw subject": {"subject_ref": "9876543210"},
            "night window": {"window": dict(self.root["window"], from_min=60)},
            "unknown channel": {"channels": ["fax"]},
            "depth": {"depth": 5, "parent_id": "p"},
            "orphan": {"depth": 1},
            "bps": {"ceilings": {"waiver_bps": 10001}},
            "unsorted": {"actions": ["send_reminder", "read_fields"]},
            "too long": {"exp": "2026-12-01T05:30:00Z"},
            "extra member": {"note": "x"},
        }
        for name, change in edits.items():
            m = dict(self.root, **change)
            with self.assertRaises(kv.Refused, msg=name):
                kv.check_mandate(m)

    def test_times_are_in_the_shortest_form(self):
        for ok in ("2026-10-01T05:30:00Z", "2026-10-01T05:30:00.500Z", "2026-10-01T05:30:00.123456Z"):
            kv.shortest_time(ok, "t")
        for bad in ("2026-10-01T05:30:00.000Z", "2026-10-01T05:30:00.500000Z",
                    "2026-10-01T05:30:00+00:00", "2026-10-01T05:30:00.5Z"):
            with self.assertRaises(kv.Refused, msg=bad):
                kv.shortest_time(bad, "t")

    def test_delegation_only_narrows(self):
        kv.check_delegation(self.child, self.root)
        wider = {
            "actions": {"actions": ["place_call", "read_fields", "teleport"]},
            "channels": {"channels": ["sms", "voice"]},
            "window": {"window": dict(self.root["window"], max_per_day=5)},
            "ceiling": {"ceilings": {"waiver_bps": 5000}},
            "later": {"exp": "2026-10-09T05:30:00Z"},
            "earlier": {"nbf": "2026-10-01T05:00:00Z"},
            "holder": {"holder": "rogue-agent"},
            "depth": {"depth": 2},
            "another purpose": {"purpose": "marketing"},
        }
        for name, change in wider.items():
            with self.assertRaises(kv.Refused, msg=name):
                kv.check_delegation(dict(self.child, **change), self.root)

    def test_event_hash_order(self):
        e = self.v["events"][1]
        shuffled = dict(reversed(list(e["payload"].items())))
        self.assertEqual(kv.event_content_sha256(shuffled), e["content_sha256"])


class Credential(unittest.TestCase):
    def test_claims_member_set_is_exact(self):
        with open(CRED, encoding="utf-8") as h:
            vector = json.load(h)
        self.assertEqual(set(vector["claims"]) - {"send_by"},
                         {"iss", "tenant", "agent", "mandate_id", "record_id", "jti", "aud",
                          "action", "req", "iat", "exp"})

    def test_aes_gcm_known_answer(self):
        # NIST GCM test case 16 (AES-256, 96-bit IV, with AAD).
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
        iv = bytes.fromhex("cafebabefacedbaddecaf888")
        aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        ct = bytes.fromhex(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662")
        tag = bytes.fromhex("76fc6ece0f4e1768cddf8853bb2d551b")
        pt = kv.aes256_gcm_open(key, iv, aad, ct, tag)
        self.assertTrue(pt.startswith(bytes.fromhex("d9313225f88406e5a55909c5aff5269a")))

    def test_x25519_rfc7748(self):
        k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        self.assertEqual(kv.x25519(k, u).hex(),
                         "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")


if __name__ == "__main__":
    unittest.main()
