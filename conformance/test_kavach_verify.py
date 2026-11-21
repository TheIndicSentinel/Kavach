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


class AgentStates(unittest.TestCase):
    def test_bundle_v3_with_a_stop_and_an_approved_reinstatement(self):
        r = kv.verify_bundle(f"{BUNDLES}/bundle-v3", f"{BUNDLES}/bundle-v2.keys.json", now=NOW)
        self.assertEqual((r["version"], r["records"], r["last_seq"]), (3, 7, 7))
        self.assertEqual(kinds(r), ["no_kept_checkpoint", "outcome_missing", "outcome_unknown"])


class Resolutions(unittest.TestCase):
    """Version 4: resolutions.jsonl, the file the manifest lists."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.bundle = os.path.join(self.dir, "b")
        shutil.copytree(f"{BUNDLES}/bundle-v4", self.bundle)
        self.keys = f"{BUNDLES}/bundle-v2.keys.json"

    def tearDown(self):
        shutil.rmtree(self.dir)

    def path(self, name):
        return os.path.join(self.bundle, name)

    def lines(self, name):
        with open(self.path(name), encoding="utf-8") as h:
            return h.read().splitlines()

    def refuse(self, fragment, cls):
        with self.assertRaises(kv.Refused) as ctx:
            kv.verify_bundle(self.bundle, self.keys, now=NOW)
        self.assertIn(fragment, str(ctx.exception))
        # The coarse class the Rust verifier must report too (spec section 10.2).
        self.assertEqual(ctx.exception.cls, cls)

    def test_a_resolved_and_a_conflicted_outcome(self):
        r = kv.verify_bundle(self.bundle, self.keys, now=NOW)
        self.assertEqual((r["version"], r["resolutions"]), (4, 3))
        # cred-3 is resolved by the provider; cred-4 holds two confirmed states.
        self.assertEqual(kinds(r), ["no_kept_checkpoint", "outcome_conflicted"])
        self.assertEqual([w["detail"] for w in r["warnings"] if w["kind"] == "outcome_conflicted"],
                         ["cred-4"])

    def test_a_missing_resolutions_file(self):
        os.remove(self.path("resolutions.jsonl"))
        self.refuse("must hold exactly", "layout")


    def test_a_removed_resolution(self):
        rows = self.lines("resolutions.jsonl")[:-1]
        with open(self.path("resolutions.jsonl"), "w", encoding="utf-8") as h:
            h.write("".join(row + "\n" for row in rows))
        self.refuse("digest does not match", "digest")

    def test_a_tampered_resolution(self):
        rows = [json.loads(row) for row in self.lines("resolutions.jsonl")]
        rows[0]["state"] = "confirmed_not_delivered"
        with open(self.path("resolutions.jsonl"), "w", encoding="utf-8") as h:
            h.write("".join(kv.jcs(row).decode() + "\n" for row in rows))
        self.refuse("digest does not match", "digest")

    def test_a_resolution_in_a_version_3_bundle_is_refused(self):
        shutil.rmtree(self.bundle)
        shutil.copytree(f"{BUNDLES}/bundle-v3", self.bundle)
        shutil.copy(f"{BUNDLES}/bundle-v4/resolutions.jsonl", self.path("resolutions.jsonl"))
        self.refuse("must hold exactly", "layout")

    def test_an_edited_manifest_is_a_manifest_failure_not_a_digest_one(self):
        with open(self.path("manifest.json"), encoding="utf-8") as h:
            manifest = json.load(h)
        manifest["files"]["resolutions"]["count"] = 9
        with open(self.path("manifest.json"), "w", encoding="utf-8") as h:
            h.write(kv.jcs(manifest).decode() + "\n")
        self.refuse("hash does not match", "manifest")

    def test_an_unknown_member_is_refused(self):
        rows = [json.loads(row) for row in self.lines("resolutions.jsonl")]
        rows[0]["note"] = "x"
        with open(self.path("resolutions.jsonl"), "w", encoding="utf-8") as h:
            h.write("".join(kv.jcs(row).decode() + "\n" for row in rows))
        self.refuse("digest does not match", "digest")


class ModelEvidence(unittest.TestCase):
    def test_bundle_v5_verifies_model_invocation_and_linked_outcome(self):
        r = kv.verify_bundle(f"{BUNDLES}/bundle-v5", f"{BUNDLES}/bundle-v2.keys.json", now=NOW)
        self.assertEqual((r["version"], r["records"], r["last_seq"]), (5, 2, 2))

    def test_bundle_v4_refuses_version_5_model_record_kinds(self):
        with open(f"{BUNDLES}/bundle-v5/manifest.json", encoding="utf-8") as handle:
            manifest = json.load(handle)
        manifest["version"] = 4
        manifest.pop("key_id", None)
        manifest.pop("sig", None)
        payload = {k: v for k, v in manifest.items() if k not in ("hash", "sig")}
        manifest["hash"] = hashlib.sha256(kv.MANIFEST_PREFIX + kv.jcs(payload)).hexdigest()
        directory = tempfile.mkdtemp()
        bundle = os.path.join(directory, "bundle")
        shutil.copytree(f"{BUNDLES}/bundle-v5", bundle)
        with open(os.path.join(bundle, "manifest.json"), "w", encoding="utf-8") as handle:
            handle.write(kv.jcs(manifest).decode() + "\n")
        try:
            with self.assertRaises(kv.Refused) as ctx:
                kv.verify_bundle(bundle, f"{BUNDLES}/bundle-v2.keys.json", now=NOW)
            self.assertIn("not in the registry for version 4", str(ctx.exception))
        finally:
            shutil.rmtree(directory)

    def test_bundle_v5_refuses_a_mismatched_invocation_hash(self):
        directory = tempfile.mkdtemp()
        bundle = os.path.join(directory, "bundle")
        shutil.copytree(f"{BUNDLES}/bundle-v5", bundle)
        try:
            with open(os.path.join(bundle, "records.jsonl"), encoding="utf-8") as handle:
                records = [json.loads(line) for line in handle]
            records[1]["invocation_hash"] = "d" * 64
            payload = {k: v for k, v in records[1].items() if k not in ("hash", "sig")}
            records[1]["hash"] = hashlib.sha256(
                kv.RECORD_PREFIX + records[1]["prev_hash"].encode("ascii") + kv.jcs(payload)
            ).hexdigest()
            raw_records = "".join(kv.jcs(row).decode() + "\n" for row in records).encode()
            with open(os.path.join(bundle, "records.jsonl"), "wb") as handle:
                handle.write(raw_records)

            with open(os.path.join(bundle, "manifest.json"), encoding="utf-8") as handle:
                manifest = json.load(handle)
            manifest["segment"]["head_hash"] = records[-1]["hash"]
            manifest["files"]["records"]["sha256"] = hashlib.sha256(raw_records).hexdigest()
            manifest.pop("key_id", None)
            manifest.pop("sig", None)
            payload = {k: v for k, v in manifest.items() if k not in ("hash", "sig")}
            manifest["hash"] = hashlib.sha256(kv.MANIFEST_PREFIX + kv.jcs(payload)).hexdigest()
            with open(os.path.join(bundle, "manifest.json"), "w", encoding="utf-8") as handle:
                handle.write(kv.jcs(manifest).decode() + "\n")

            with mock.patch.object(kv.Verifier, "_check_sig", lambda *args, **kwargs: None):
                with self.assertRaises(kv.Refused) as ctx:
                    kv.verify_bundle(bundle, f"{BUNDLES}/bundle-v2.keys.json", now=NOW)
            self.assertIn("does not link to its invocation", str(ctx.exception))
        finally:
            shutil.rmtree(directory)


class DigestForms(unittest.TestCase):
    def test_bundle_with_a_tagged_event_digest(self):
        r = kv.verify_bundle(f"{BUNDLES}/bundle-v2-digest", f"{BUNDLES}/bundle-v2.keys.json",
                             now=NOW)
        self.assertEqual(r["records"], 5)
        self.assertEqual(kinds(r), ["no_kept_checkpoint", "outcome_missing", "outcome_unknown"])


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

    def refuse(self, fragment, cls=None):
        with self.assertRaises(kv.Refused) as ctx:
            kv.verify_bundle(self.bundle, self.keys, now=NOW)
        self.assertIn(fragment, str(ctx.exception))
        if cls is not None:
            self.assertEqual(ctx.exception.cls, cls)

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
        self.refuse("digest does not match", "digest")

    def test_manifest_edit(self):
        m = self.rows("manifest.json")[0]
        m["exporter"]["tool"] = "other"
        self.write("manifest.json", [m])
        self.refuse("hash does not match")

    def test_removed_checkpoint_file_line(self):
        rows = self.rows("checkpoints.jsonl")[:-1]
        self.write("checkpoints.jsonl", rows)
        self.refuse("digest does not match", "digest")

    def test_extra_file(self):
        open(self.path("notes.txt"), "w").close()
        self.refuse("must hold exactly", "layout")

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

    def test_a_revocation_states_exactly_one_digest(self):
        legacy = "ab" * 32
        for what, edit in {
            "both": lambda r: r.update(event_sha256=legacy, event_digest=kv.EVENT_DIGEST_PREFIX + legacy),
            "neither": lambda r: (r.pop("event_sha256", None), r.pop("event_digest", None)),
            "short": lambda r: (r.pop("event_sha256", None), r.update(event_digest="sha256-jcs-v1:ab")),
            "unknown tag": lambda r: (r.pop("event_sha256", None), r.update(event_digest="sha512:" + legacy)),
            "upper case": lambda r: (r.pop("event_sha256", None),
                                     r.update(event_digest=kv.EVENT_DIGEST_PREFIX + legacy.upper())),
        }.items():
            with self.subTest(what):
                shutil.rmtree(self.bundle)
                shutil.copytree(f"{BUNDLES}/bundle-v2", self.bundle)
                rows = self.rows("records.jsonl")
                edit(rows[4])
                self.reseal(rows)
                with self.structural():
                    self.refuse("exactly one well-formed event digest")

    def _v3(self):
        shutil.rmtree(self.bundle)
        shutil.copytree(f"{BUNDLES}/bundle-v3", self.bundle)
        return self.rows("records.jsonl")

    def test_agent_state_rules_hold_even_when_signed(self):
        cases = {
            "same state": (5, {"to_state": "active"}),
            "revoked is never changed": (5, {"from_state": "revoked", "to_state": "active",
                                               "approved_by": "ops-9"}),
            "unknown state": (5, {"to_state": "frozen"}),
            "free text reason": (5, {"reason_code": "the borrower Asha called"}),
            "bad digest": (5, {"reason_digest": "mac:abc"}),
            "tightening names an approver": (5, {"approved_by": "ops-2"}),
            "loosening without approver": (6, {"approved_by": None}),
            "approves their own change": (6, {"approved_by": "ops-kat-1"}),
            "change number zero": (5, {"change_no": 0}),
            "request id on a tightening": (5, {"change_request_id": "cr-1"}),
            "empty request id": (6, {"change_request_id": ""}),
        }
        for what, (index, edit) in cases.items():
            with self.subTest(what):
                rows = self._v3()
                rows[index].update(edit)
                self.reseal(rows)
                with self.structural():
                    self.refuse("malformed record")

    def test_a_loosening_may_name_the_change_request_that_carried_it_out(self):
        rows = self._v3()
        reinstatement = dict(rows[6], change_request_id="cr-7f3a")
        kv.Verifier._agent_state_form(reinstatement, "record 7")
        # ...and a tightening may not.
        stop = dict(rows[5], change_request_id="cr-7f3a")
        with self.assertRaises(kv.Refused):
            kv.Verifier._agent_state_form(stop, "record 6")

    def test_a_version_2_bundle_refuses_an_agent_state_record(self):
        rows = self._v3()
        manifest = self.rows("manifest.json")[0]
        manifest["version"] = 2
        self.write("records.jsonl", rows)
        self.seal_manifest(manifest)
        with self.structural():
            self.refuse("registry")

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
        self.assertEqual(len(r["binding_refused"]), len(self.v["binding_refused"]))

    def test_digest_is_of_the_signed_bytes_and_tagged(self):
        e = self.v["events"][0]
        self.assertTrue(e["event_digest"].startswith("sha256-jcs-v1:"))
        self.assertNotEqual(e["event_digest"].split(":")[1], e["legacy_content_sha256"])

    def test_form_rules(self):
        kv.check_mandate(self.root)
        edits = {
            "version": ({"mv": 2}, "unknown mandate version"),
            "raw subject": ({"subject_ref": "9876543210"}, "capability reference"),
            "night window": ({"window": dict(self.root["window"], from_min=60)}, "08:00-19:00"),
            "unknown channel": ({"channels": ["fax"]}, "unknown channel"),
            "depth": ({"depth": 5, "parent_id": "p"}, "above the limit"),
            "orphan": ({"depth": 1}, "disagree"),
            "bps": ({"ceilings": {"waiver_bps": 10001}}, "out of range"),
            "unsorted": ({"actions": ["send_reminder", "read_fields"]}, "not sorted"),
            "too long": ({"exp": "2026-12-01T05:30:00Z"}, "lifetime"),
            "extra member": ({"note": "x"}, "must not have"),
        }
        for name, (change, why) in edits.items():
            with self.assertRaisesRegex(kv.Refused, why, msg=name):
                kv.check_mandate(dict(self.root, **change))

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
        why = {
            "actions": "actions are not within", "channels": "channels are not within",
            "window": "window is not within", "ceiling": "ceiling waiver_bps exceeds",
            "later": "outlives", "earlier": "starts before", "holder": "not a valid delegation",
            "depth": "not a valid delegation", "another purpose": "must keep",
        }
        for name, change in wider.items():
            with self.assertRaisesRegex(kv.Refused, why[name], msg=name):
                kv.check_delegation(dict(self.child, **change), self.root)

    def test_digest_does_not_depend_on_member_order(self):
        e = self.v["events"][1]
        shuffled = dict(reversed(list(e["payload"].items())))
        self.assertEqual(kv.event_digest(shuffled), e["event_digest"])
        self.assertEqual(kv.legacy_content_sha256(shuffled), e["legacy_content_sha256"])


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
