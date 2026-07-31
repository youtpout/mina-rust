# Block proof generation: a regression, its cause, and its fix

Investigated 2026-07-30/31 on `devnet-block-proving`, off `upstream/develop`
`82480cd4`. Host aarch64-apple-darwin, proof-systems `o1-labs` tag `0.3.0`.

## Summary

Block proof generation had been broken for eleven months. The step witness for
the blockchain SNARK no longer satisfied the circuit's copy constraints, so no
block proof could be produced at all. `status.md` listed it as working, the
code compiled, and nothing failed loudly, because the tests that would have
caught it were disabled the day the bug landed.

The cause is the proof system and algebra bump of 2025-09-03, a five-commit
series migrating to a new kimchi API. Three pieces of semantics were lost in
it. They are restored in the accompanying commit, and `test_block_proof`
passes again with step and wrap timings equal to the last known good commit.

## How it stayed hidden

`ff9e4d35a` "Updated tests" (2025-09-04 12:59) marked all six proof tests
`#[ignore = "Failing due to circuits"]`, the day after the bump. The stated
cause is wrong, and that matters: `ROWS` matches the circuit blobs exactly, so
the circuits were never in question. The witness had diverged. An accurate
label would have pointed at the migration; "circuits" pointed at something
nobody could act on.

CI compounded it. `make test-ledger` runs `cargo test --release` without
`--ignored`, so once the tests were marked, they ran nowhere. Eleven months of
green builds over a feature that could not produce a single proof.

## The three defects

**`plonk_checks.rs`, `const_eval`.** A `ConstantExpr` depends only on constants
and challenges, so it is evaluated out of circuit; only the top-level `Mul` is
witnessed. The migration replaced this with a recursive `sub_eval` calling
`field::mul` and `pow`, which allocate a witness value at every `Mul`, `Square`
and `Pow` of the tree. Worth 364 of the 372 extra values. The pre-migration
behaviour was still described in a doc comment left on `sub_eval`.

**`plonk_checks.rs`, `is_const`.** The recursion through binary operations was
commented out rather than ported to the new `Add`/`Mul`/`Sub` variants, so a
combination of constants stopped being recognised as constant and `eval` took
its witness-allocating branch. Worth the remaining 4.

**`group_map.rs`, `is_square`.** Euler's criterion needs the modulus of `F`,
but the migration hardcoded `Fp`'s. Every call on `Fq` — the entire wrap side —
used the wrong exponent, and `sqrt_exn` then unwrapped a non-residue. This is
why the step proof succeeded and the wrap did not, on the transaction path as
well as the block path.

## How it was found

Two independent reproductions first: the captured 2024 fixture, and a block
built by the current code with no fixture involved. Both reported
`witness_aux: 339245` against a declared 338873, with identical
`prev_challenges_hash` and `group_map_hash` — structural, not data-dependent.

Bisect over the 105 commits touching the proof code, using the
`compute_witness` assertion as the predicate:

| commit | date | verdict |
|---|---|---|
| `c56af6044` | 2024-10-09 | good |
| `9579a9858` | 2025-02-04 | good |
| `5a4ab5d35` | 2025-08-21 | good |
| `c8c7fe1b6` | 2025-08-28 | good |
| `691997df6` | 2025-09-03 | bad |
| `7d172086c` | 2025-10-07 | bad |
| `640fe24d2` | 2025-12-16 | bad |

`84597dfae`, first of the series, does not build on its own: it is a mid-PR
commit whose errors the follow-ups fix. Probe the last of the series.

Localisation then came from diffing witnesses rather than guessing. Dumping
the auxiliary vector at `c8c7fe1b6` and on the broken tree put the first
divergence at index 52749, and a trap in `Witness::exists_no_check` firing at
that index produced a backtrace landing in `plonk_checks::scalars::pow` under
`sub_eval`, `ft_eval0_checked`, `finalize_other_proof`, `verify_one`. Two
earlier hypotheses had been wrong; this one was not a hypothesis.

That `verify_one` runs once per previously verified proof also explains why
every discrepancy was even: the block circuit verifies two.

## Traps worth knowing before rerunning any of this

Four separate false negatives cost a full bisect pass. Each makes a broken
commit look healthy, which is the same failure mode that hid the bug.

- `--ignored` runs *only* ignored tests. Before 2025-09-04 these tests carried
  no `#[ignore]`, so the filter matched nothing. Use `--include-ignored`.
- cargo rewrites `Cargo.lock` on every build, which makes the next
  `git checkout` fail; the commit is then silently never tested. Reset the
  lock before switching revisions.
- the devnet circuits directory was renamed twice: `3.0.1devnet`, then
  `3.0.0devnet`, then `berkeley-devnet` (2025-10-06). When its fixture is
  missing the test *returns silently*. `circuit-blobs` renamed with identical
  contents and identical file hashes, and the old releases still exist, so
  staging fixtures under all three names and symlinking the blob cache
  accordingly covers the whole range.
- detecting the ledger crate with `[ -d crates/ledger ]` is unreliable, since
  untracked leftovers keep the directory alive across checkouts of revisions
  predating the reorganization. Test for `Cargo.toml`.

## Validation

- `test_block_proof` passes: step 3.2 s, wrap 1.2 s, against 2.8 s / 1.1 s at
  `c8c7fe1b6`.
- The block step witness is back to exactly 338873 auxiliary values.
- Of the six previously ignored proof tests, 12 of 13 cases pass. Their
  `AUX_LEN` assertions passing means the block, transaction, merge and both
  zkapp circuits all produce pre-migration witness counts.
- Full ledger suite: 150 passed, 0 failed.
- `block_production_full_proof`, added here, produces a block with a real
  proof end to end. Every other block-production scenario runs with
  `ProofKind::Dummy` (the default in `tools/testing/src/cluster/config.rs`), so
  none of them exercised the proving stack.

Not resolved: `test_proofs` compares a serialized proof against a golden
sha256 recorded 2024-09-24. It passes at `c8c7fe1b6` and fails here. A hash
alone cannot separate "kimchi changed the serialization" from "the proof is
wrong", so it needs its own answer rather than a re-record.

**Everything above is self-consistent within this implementation. No third
party has yet accepted one of these proofs.** The decisive check is to have a
proof produced by this branch verified by an OCaml node, and it has not been
done.

## Reproducing

Fixtures are not in the repo. `make download-circuits` clones all of
`o1-labs/circuit-blobs` and needs `gsed` on macOS; fetching what is needed is
enough:

```bash
mkdir -p crates/ledger/berkeley-devnet/tests
cd crates/ledger/berkeley-devnet/tests
for f in block_input-2483246-0 command-0-1 command-1-0 merge-100-0 \
         zkapp-command-with-proof-128-1; do
  curl -sfL -O "https://raw.githubusercontent.com/o1-labs/circuit-blobs/main/berkeley-devnet/tests/$f.bin"
done
```

The circuit blobs themselves are fetched on demand and cached under
`~/.mina/circuit-blobs/`, per the lookup in `proofs/circuit_blobs.rs`.

```bash
# captured fixture, ~20 s
cargo test -r -p mina-tree --lib proofs::transaction::tests::test_block_proof \
  -- --include-ignored --nocapture

# a block built by the current code, no fixture, ~55 s
cargo test -r --package mina-node-testing --test block_production_full_proof \
  -- block_production_full_proof --exact --nocapture
```

## Follow-ups

1. Have an OCaml node verify a proof from this branch. Nothing else settles it.
2. Drop `#[ignore]` from the five tests that now pass, so CI guards this.
   `make test-ledger` depends on `download-circuits`, so the fixtures are
   available there. This is what prevents a recurrence.
3. Answer `test_proofs` rather than re-recording its hash.
4. Upstream the fix: the bug is in `o1-labs/mina-rust@develop`, not only here.
5. Block proof failure panics on a `todo!()` at
   `crates/node/src/event_source/event_source_effects.rs:487` instead of being
   handled.

## Unrelated note on proof-systems 0.7

Upstream PR #3514 changed the `EndoSclMul` gate from 11 to 12 constraints,
present in every tag from `0.5.0` and still on `master`:

    0.3.0: 11    0.4.0: 11    0.5.0: 12    0.6.0: 12    0.7.0: 12

That changes the linearization and therefore verification keys, so 0.7 as-is
does not match the circuits deployed on devnet today. Whether it targets the
Mesa upgrade is not stated in the changelog and was not verified here. The
`youtpout/proof-systems@pickle-rs` fork reverts it to 11. This is orthogonal
to the regression above, which is a witness-vs-circuit mismatch that kimchi
merely reports.
