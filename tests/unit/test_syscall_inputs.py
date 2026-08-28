"""Behavior tests for the syscall-input contract utility."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from specula import cli, syscall_inputs


class TestPublicCommand(unittest.TestCase):
    def test_help_exposes_generate_and_validate_without_launching_a_phase(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        # Python 3.14 argparse honors FORCE_COLOR even for non-tty streams;
        # pin colors off so the help text stays byte-comparable.
        with (
            mock.patch.dict("os.environ", {"PYTHON_COLORS": "0"}),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            rc = cli.main(["syscall-inputs", "--help"])

        self.assertEqual(rc, 0)
        self.assertEqual(err.getvalue(), "")
        self.assertIn("usage: specula syscall-inputs", out.getvalue())
        self.assertIn("generate", out.getvalue())
        self.assertIn("validate", out.getvalue())

    def test_generate_expands_usercopy_boundaries_from_contract_values(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            contract = tmp / "contract.json"
            output = tmp / "cases.json"
            contract.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "artifact": "syscall-input-contract",
                        "campaign": "unseen-family",
                        "page_size": 16,
                        "max_cases": 100,
                        "syscalls": [
                            {
                                "name": "copy_in",
                                "direction": "user-to-kernel",
                                "shape": "buffer",
                                "lengths": [0, 1, 17, 48],
                                "pointer_regions": ["valid", "guard-page"],
                            }
                        ],
                    }
                )
            )

            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = cli.main(
                    [
                        "syscall-inputs",
                        "generate",
                        "--contract",
                        str(contract),
                        "--output",
                        str(output),
                    ]
                )

            self.assertEqual((rc, err.getvalue()), (0, ""))
            document = json.loads(output.read_text())
            self.assertEqual(document["artifact"], "syscall-input-cases")
            self.assertEqual(document["campaign"], "unseen-family")
            self.assertRegex(document["contract_sha256"], r"^[0-9a-f]{64}$")
            self.assertFalse(document["generation"]["truncated"])

            guard_boundaries = {
                case["input"]["objects"][0]["accessible_units"]
                for case in document["cases"]
                if case["requested_length"] == 17
                and case["input"]["objects"][0]["region"] == "guard-page"
            }
            self.assertEqual(guard_boundaries, {0, 1, 15, 16, 17})
            long_guard_boundaries = {
                case["input"]["objects"][0]["accessible_units"]
                for case in document["cases"]
                if case["requested_length"] == 48
                and case["input"]["objects"][0]["region"] == "guard-page"
            }
            self.assertEqual(long_guard_boundaries, {0, 1, 15, 16, 17, 31, 32, 33, 47, 48})
            valid = [
                case
                for case in document["cases"]
                if case["requested_length"] == 17
                and case["input"]["objects"][0]["region"] == "valid"
            ]
            self.assertEqual(len(valid), 1)
            self.assertEqual(valid[0]["input"]["objects"][0]["accessible_units"], 17)

    def test_generate_preserves_iovec_alias_graphs_and_faults_metadata_or_payload(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            contract = tmp / "contract.json"
            output = tmp / "cases.json"
            contract.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "artifact": "syscall-input-contract",
                        "campaign": "heldout-iovec-family",
                        "page_size": 8,
                        "max_cases": 500,
                        "syscalls": [
                            {
                                "name": "vector_copy",
                                "direction": "kernel-to-user",
                                "shape": "iovec",
                                "lengths": [1, 4],
                                "pointer_regions": ["valid", "guard-page"],
                                "iov_counts": [2],
                                "alias_topologies": ["identical", "partial-overlap"],
                                "fault_paths": ["metadata", "payload"],
                            }
                        ],
                    }
                )
            )

            rc = cli.main(
                [
                    "syscall-inputs",
                    "generate",
                    "--contract",
                    str(contract),
                    "--output",
                    str(output),
                ]
            )

            self.assertEqual(rc, 0)
            cases = json.loads(output.read_text())["cases"]
            identical = next(
                case
                for case in cases
                if case["input"].get("alias_topology") == "identical"
                and case["requested_length"] == 8
                and not case["fault_paths"]
            )
            self.assertEqual(
                [edge["object_id"] for edge in identical["input"]["edges"]],
                ["buffer-0", "buffer-0"],
            )

            overlap = next(
                case
                for case in cases
                if case["input"].get("alias_topology") == "partial-overlap"
                and case["requested_length"] == 8
                and not case["fault_paths"]
            )
            self.assertEqual([edge["offset"] for edge in overlap["input"]["edges"]], [0, 2])
            self.assertFalse(
                any(
                    case["input"].get("alias_topology") == "partial-overlap"
                    and case["requested_length"] == 2
                    for case in cases
                ),
                "one-byte elements cannot partially overlap without being identical",
            )

            metadata_fault = next(
                case
                for case in cases
                if "iovec-metadata" in case["fault_paths"]
                and next(obj for obj in case["input"]["objects"] if obj["id"] == "iovec")[
                    "accessible_units"
                ]
                == 1
            )
            metadata = next(obj for obj in metadata_fault["input"]["objects"] if obj["id"] == "iovec")
            self.assertEqual((metadata["unit"], metadata["access_direction"]), ("entry", "user-to-kernel"))

            payload_fault = next(
                case
                for case in cases
                if "iov[0].base" in case["fault_paths"]
                and next(obj for obj in case["input"]["objects"] if obj["id"] == "buffer-0")[
                    "accessible_units"
                ]
                == 1
            )
            self.assertEqual(payload_fault["copy_direction"], "kernel-to-user")

            only_impossible = json.loads(contract.read_text())
            only_impossible["syscalls"][0]["lengths"] = [1]
            only_impossible["syscalls"][0]["alias_topologies"] = ["partial-overlap"]
            contract.write_text(json.dumps(only_impossible))
            with contextlib.redirect_stderr(err := io.StringIO()):
                rc = cli.main(
                    [
                        "syscall-inputs",
                        "generate",
                        "--contract",
                        str(contract),
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(rc, 2)
            self.assertIn("no applicable input combinations", err.getvalue())

    def test_iovec_generation_normalizes_semantically_irrelevant_dimensions(self) -> None:
        document = syscall_inputs.generate_cases(
            {
                "schema_version": 1,
                "artifact": "syscall-input-contract",
                "campaign": "degenerate-iovec-dimensions",
                "page_size": 4096,
                "max_cases": 10,
                "syscalls": [
                    {
                        "name": "vector_copy",
                        "direction": "user-to-kernel",
                        "shape": "iovec",
                        "lengths": [1, 4],
                        "pointer_regions": ["valid"],
                        "iov_counts": [0, 1],
                        "alias_topologies": ["disjoint", "identical", "partial-overlap"],
                    }
                ],
            }
        )

        self.assertEqual(document["generation"]["candidate_count"], 3)
        self.assertEqual(
            [
                (case["requested_length"], case["input"]["alias_topology"])
                for case in document["cases"]
            ],
            [(0, "none"), (1, "single"), (4, "single")],
        )

    def test_generation_is_direction_aware_and_reports_caps(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            contract = tmp / "contract.json"
            output = tmp / "cases.json"
            contract.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "artifact": "syscall-input-contract",
                        "campaign": "family-a",
                        "page_size": 16,
                        "max_cases": 20,
                        "syscalls": [
                            {
                                "name": "copy_in",
                                "direction": "user-to-kernel",
                                "shape": "buffer",
                                "lengths": [8],
                                "pointer_regions": ["read-only"],
                            },
                            {
                                "name": "copy_out",
                                "direction": "kernel-to-user",
                                "shape": "buffer",
                                "lengths": [8],
                                "pointer_regions": ["read-only"],
                            },
                        ],
                    }
                )
            )
            self.assertEqual(
                cli.main(
                    [
                        "syscall-inputs",
                        "generate",
                        "--contract",
                        str(contract),
                        "--output",
                        str(output),
                    ]
                ),
                0,
            )
            cases = json.loads(output.read_text())["cases"]
            by_name = {case["syscall"]: case for case in cases}
            self.assertEqual(by_name["copy_in"]["fault_paths"], [])
            self.assertEqual(by_name["copy_out"]["fault_paths"], ["buffer"])

            raw = json.loads(contract.read_text())
            raw["syscalls"] = [
                {
                    "name": "bounded_copy",
                    "direction": "user-to-kernel",
                    "shape": "buffer",
                    "lengths": [17],
                    "pointer_regions": ["guard-page"],
                }
            ]
            raw["max_cases"] = 2
            contract.write_text(json.dumps(raw))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(
                    cli.main(
                        [
                            "syscall-inputs",
                            "generate",
                            "--contract",
                            str(contract),
                            "--output",
                            str(output),
                        ]
                    ),
                    3,
                )
            document = json.loads(output.read_text())
            self.assertEqual(
                document["generation"],
                {"candidate_count": 5, "emitted_count": 2, "max_cases": 2, "truncated": True},
            )
            self.assertIn("2/5 cases (truncated)", out.getvalue())
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    cli.main(
                        [
                            "syscall-inputs",
                            "validate",
                            str(output),
                            "--contract",
                            str(contract),
                        ]
                    ),
                    3,
                )

    def test_validate_binds_evidence_sidecar_to_generated_cases(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            contract = tmp / "contract.json"
            cases_path = tmp / "cases.json"
            evidence = tmp / "evidence.json"
            contract.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "artifact": "syscall-input-contract",
                        "campaign": "blind-holdout",
                        "page_size": 16,
                        "max_cases": 20,
                        "syscalls": [
                            {
                                "name": "copy_out",
                                "direction": "kernel-to-user",
                                "shape": "buffer",
                                "lengths": [17],
                                "pointer_regions": ["guard-page"],
                            }
                        ],
                    }
                )
            )
            self.assertEqual(
                cli.main(
                    [
                        "syscall-inputs",
                        "generate",
                        "--contract",
                        str(contract),
                        "--output",
                        str(cases_path),
                    ]
                ),
                0,
            )
            cases = json.loads(cases_path.read_text())
            evidence_file = tmp / "harness" / "non-tla" / "evidence" / "copy-out.ndjson"
            evidence_file.parent.mkdir(parents=True)
            evidence_file.write_text("{\"observed\":true}\n")
            evidence.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "artifact": "syscall-input-evidence",
                        "campaign": "blind-holdout",
                        "contract_sha256": cases["contract_sha256"],
                        "cases_sha256": hashlib.sha256(cases_path.read_bytes()).hexdigest(),
                        "target": {"name": "target-under-test", "identity": "commit-abc", "smp": 2},
                        "executions": [
                            {
                                "case_id": cases["cases"][0]["id"],
                                "status": "candidate",
                                "oracle": "usercopy-boundary",
                                "observations": {
                                    "result": {"return": -1, "errno": "EFAULT"},
                                    "progress": {
                                        "attempted": 17,
                                        "copied": 1,
                                        "committed": 1,
                                        "reported": 0,
                                        "offset_advanced": 0,
                                    },
                                    "state_before": {},
                                    "state_after": {},
                                },
                                "evidence": ["harness/non-tla/evidence/copy-out.ndjson"],
                            }
                        ],
                    }
                )
            )

            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = cli.main(
                    [
                        "syscall-inputs",
                        "validate",
                        str(evidence),
                        "--contract",
                        str(contract),
                        "--cases",
                        str(cases_path),
                        "--work-dir",
                        str(tmp),
                    ]
                )
            self.assertEqual((rc, err.getvalue()), (0, ""))
            self.assertIn("valid syscall-input-evidence", out.getvalue())
            self.assertIn("1 execution", out.getvalue())

            bad = json.loads(evidence.read_text())
            bad["executions"][0]["case_id"] = "uc-not-generated"
            evidence.write_text(json.dumps(bad))
            with contextlib.redirect_stderr(err := io.StringIO()):
                rc = cli.main(
                    [
                        "syscall-inputs",
                        "validate",
                        str(evidence),
                        "--contract",
                        str(contract),
                        "--cases",
                        str(cases_path),
                        "--work-dir",
                        str(tmp),
                    ]
                )
            self.assertEqual(rc, 2)
            self.assertIn("unknown case_id", err.getvalue())


if __name__ == "__main__":
    unittest.main()
