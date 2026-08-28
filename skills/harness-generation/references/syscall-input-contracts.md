# Syscall-input contracts and non-TLA evidence

Use this overlay when the target crosses a syscall boundary with user-controlled
pointers, lengths, flags, nested structures, or fallible user copies. It adds
executable cases to Phase 2.5; it does not replace the ordinary trace harness.

## Artifact interface

Keep all three artifacts under `harness/non-tla/`:

| Artifact | Producer | Consumer |
|---|---|---|
| `contract.json` | Phase 2.5 agent after source/contract review | `specula syscall-inputs generate` |
| `cases.json` | deterministic Specula generator | target-specific harness adapter |
| `evidence.json` | real target executions | `specula syscall-inputs validate`, then a later evidence-review phase |

The files are a sidecar. `spec/findings.json` remains model-checking-only.
A `candidate` observation is evidence to investigate, not a confirmed bug.

## 1. Freeze the contract

Derive the contract from the supported syscall interface, source-level copy
and validation paths, and the campaign's stated scope. Use target-neutral
input classes. Holdout labels, known-bug reports, fixing patches, and expected
fault locations are not contract inputs.

Write `contract.json`:

```json
{
  "schema_version": 1,
  "artifact": "syscall-input-contract",
  "campaign": "one-shared-state-machine",
  "page_size": 4096,
  "max_cases": 10000,
  "syscalls": [
    {
      "name": "vector_operation",
      "direction": "kernel-to-user",
      "shape": "iovec",
      "lengths": [0, 1, 4095, 4096, 4097],
      "pointer_regions": [
        "valid",
        "null",
        "unmapped",
        "prot-none",
        "read-only",
        "guard-page"
      ],
      "iov_counts": [0, 1, 2, 3],
      "alias_topologies": [
        "disjoint",
        "identical",
        "adjacent",
        "partial-overlap"
      ],
      "fault_paths": ["metadata", "payload"],
      "observations": ["shared-object-state"]
    }
  ]
}
```

Contract fields:

- `direction`: `user-to-kernel`, `kernel-to-user`, or `bidirectional`.
- `shape`: `buffer` or `iovec`.
- `lengths`: interface-derived edge classes. Include zero, one, and relevant
  page/ABI boundaries; do not insert a value because one known bug needs it.
- `pointer_regions`: abstract mappings the target adapter must materialize.
- `iov_counts`: descriptor-count classes for an `iovec` shape.
- `alias_topologies`: graph relations between entries and backing objects. Counts zero/one are labeled `none`/`single`; `partial-overlap` applies only when at least two entries have lengths of two bytes or more.
- `fault_paths`: top-level descriptor metadata, nested payload, or both.
- `observations`: extra target state to capture in addition to the standard
  result/progress/sentinel/offset/resource ledger.

Validate before generation:

```sh
specula syscall-inputs validate harness/non-tla/contract.json
```

Completion criterion: the contract contains every in-scope input class and no
case selected from benchmark outcomes or known finding locations.

## 2. Generate deterministic cases

Run:

```sh
specula syscall-inputs generate \
  --contract harness/non-tla/contract.json \
  --output harness/non-tla/cases.json

specula syscall-inputs validate \
  harness/non-tla/cases.json \
  --contract harness/non-tla/contract.json
```

The generator expands byte-`k` edge/page boundaries, direction-sensitive
mapping permissions, iovec metadata faults, and alias-preserving payload
graphs. Case IDs are content-derived. A truncated generation writes the
inspectable prefix with `generation.truncated=true`, prints `(truncated)`, and
returns exit 3. Narrow the contract or raise its reviewed `max_cases`; a
truncated prefix does not satisfy Phase 2.5 coverage.

`cases.json` is immutable after generation. Change the contract and regenerate
instead of hand-editing a case.

## 3. Materialize real target inputs

Write a target-language adapter under `harness/src/` that maps each abstract
object to real userspace memory:

- `valid`: fully accessible for the requested direction.
- `null`, `unmapped`, `prot-none`, `noncanonical`, `kernel-range`: platform-
  appropriate invalid addresses, only when the target ABI admits the class.
- `read-only`: readable by kernel input copies and unwritable by kernel output
  copies.
- `guard-page`: an accessible prefix followed by an inaccessible mapping at
  `accessible_units`.
- iovec edges: preserve the generated object IDs, offsets, lengths, and alias
  topology. Separate allocations for `disjoint`; one shared allocation for
  the other topologies.

The adapter must run the real syscall path. It may use analysis-only hooks to
localize a copy site, but the evidence must identify those runs and Phase 4
must prefer a public guard-page reproduction.

Capture before/after state and sentinels. Keep these progress values separate:
`attempted`, `copied`, `committed`, `reported`, and `offset_advanced`. Use
`null` when a value cannot be observed; zero means it was observed as zero.

## 4. Write the evidence sidecar

Write `evidence.json` only from executed cases:

```json
{
  "schema_version": 1,
  "artifact": "syscall-input-evidence",
  "campaign": "one-shared-state-machine",
  "contract_sha256": "<digest copied from cases.json>",
  "cases_sha256": "<sha256 of the exact cases.json bytes>",
  "target": {
    "name": "target-under-test",
    "identity": "immutable source/build identity",
    "smp": 2
  },
  "executions": [
    {
      "case_id": "uc-0123456789abcdef",
      "status": "candidate",
      "oracle": "usercopy-boundary",
      "observations": {
        "result": {"return": -1, "errno": "EFAULT"},
        "progress": {
          "attempted": 4097,
          "copied": 1,
          "committed": 0,
          "reported": 0,
          "offset_advanced": 0
        },
        "state_before": {},
        "state_after": {}
      },
      "evidence": ["harness/non-tla/evidence/vector-operation.ndjson"]
    }
  ]
}
```

Allowed execution statuses are `pass`, `candidate`, `unsupported`, `not-run`,
and `harness-error`. Unsupported and harness failures stay visible in the
sidecar and coverage totals. Paths are relative to the run work directory.

Bind and validate the exact artifacts:

```sh
specula syscall-inputs validate \
  harness/non-tla/evidence.json \
  --contract harness/non-tla/contract.json \
  --cases harness/non-tla/cases.json \
  --work-dir .
```

Validation requires each cited evidence path to exist, be non-empty, and remain
under `--work-dir`. Completion criterion: every recorded execution references a
generated case, the sidecar validates, truncated/unexecuted/unsupported counts
are reported, and no entry has been copied into `spec/findings.json`.

## Evaluation discipline

- Treat campaigns used to design the contract as regression suites, not
  effectiveness measurements.
- Freeze and hash the contract before an unseen syscall family is opened.
- Keep seeded positive controls in a separate run ID and agent context.
- Include legal partial transfers, permitted errno alternatives, unsupported
  inputs, and post-effect output faults as negative controls.
- Report generated, emitted, executed, candidate, reproduced, and confirmed
  denominators separately.
- Mutation operators measure sensitivity only. A seeded mutant is never a
  novel finding.
