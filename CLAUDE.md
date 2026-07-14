# Mina Codebase Navigation Guide

This file helps understand and navigate the Mina codebase structure.

## Project Overview

Mina is a Rust implementation of the Mina Protocol, a lightweight blockchain
using zero-knowledge proofs. It follows a Redux-style state machine architecture
for predictable, debuggable behavior.

## o1js Rust backend integration (`pickle-rs`)

The `pickle-rs` branch is the integration base for replacing o1js' Mina OCaml
and jsoo runtime with this Rust implementation. This repository is the intended
high-level backend because it already contains the Ledger, Mina transaction
logic, protocol types, signer, and SNARK verification orchestration. Pickles and
Snarky themselves remain in the proof-systems repository.

All active proof-systems dependencies must come from:

```text
https://github.com/youtpout/proof-systems
branch: pickle-rs
```

`Cargo.lock` pins the tested commit. Do not mix crates from the official
`o1-labs/proof-systems` tag with crates from the fork: Kimchi, Pasta curves,
Poseidon, signer, hasher, polynomial commitment, and o1-utils must resolve from
one revision to avoid duplicate types and transcript incompatibilities.

Initial compatibility work for proof-systems 0.7 includes:

- the public `SRS::lagrange_bases()` / `set_once()` cache API;
- `std::sync::OnceLock` in Kimchi verifier indexes;
- `ScalarChallenge::inner()` instead of tuple-field access;
- explicit `NonceMode::Legacy` / `NonceMode::Chunked` signer calls.

The first validated milestone is that both `mina-tree` (Ledger) and
`mina-snark` compile against the fork. The migration must proceed without
replacing o1js' `src/mina` directory in place until a stable Rust adapter exists.

Validation on this branch:

- `cargo check -p mina-cli -p mina-node -p mina-snark -p mina-tree` passes;
- the Ledger unit suite has 149 passing tests and 6 pre-existing circuit tests
  ignored;
- `proofs::transaction::tests::test_convert_requests` requires the external
  devnet circuit `tests` directory and fails with `ENOENT` when those fixtures
  are not installed; this is not a proof-systems compatibility failure.

The production dependency direction is deliberately one-way:

```text
o1js -> mina-rust o1js adapter -> proof-systems (pickle-rs)
```

o1js must not also depend directly on proof-systems in production. The adapter
owns the Pickles `compile`, `prove`, and `verify` entry points and exposes stable,
versioned wire types over NAPI/WASM. Direct o1js-to-proof-systems dependencies
are allowed only in temporary parity tests and development tooling. This avoids
resolving two Pickles/Kimchi revisions and keeps Mina Ledger, transaction, and
proof serialization semantics behind one Rust boundary.

Next integration milestones:

1. **Core adapter crate.** Add a transport-independent `mina-runtime` crate to
   this workspace. It owns session/handle lifetimes and depends on `mina-tree`,
   Mina protocol types, and the `pickles`/`snarky` crates from the same locked
   proof-systems revision. No JavaScript ABI types belong in this crate.
2. **Stable backend contract.** Expose versioned request/response types for
   Ledger and account operations, transaction construction/signing, circuit
   registration, `compile`, `prove`, `verify`, key serialization, and proof
   serialization. Define explicit backend and wire-format version queries so
   o1js can reject incompatible binaries instead of silently mis-decoding data.
3. **Native transport.** Add a thin NAPI crate over `mina-runtime`. Move the
   existing experimental Rust Pickles calls in o1js behind this façade and test
   cancellation, concurrent proving, cache ownership, and structured errors.
4. **Browser transport.** Add a thin `wasm-bindgen` crate over the same core
   contract. NAPI and WASM must consume identical serialized requests and
   produce byte-identical keys/proofs for deterministic fixtures where the
   protocol permits it.
5. **o1js backend switch.** Introduce one internal backend interface in o1js and
   route `ZkProgram`, `SmartContract`, Ledger, transaction, signer, and encoding
   operations through it. Rust becomes opt-in first, then the default; jsoo
   remains available only as the comparison backend during migration.
6. **Parity and release gate.** Run the existing o1js suites against both
   backends and compare gates, verification keys, proofs, Mina wire/binprot
   values, errors, and native/browser behavior. Add cold/warm compile and prove
   benchmarks and memory checks. Publish only when Rust verifies jsoo artifacts
   and jsoo verifies Rust artifacts for all supported circuit shapes.
7. **Remove jsoo and Mina OCaml.** Delete the jsoo bindings, OCaml build and
   runtime assets, dual-backend flag, and direct production proof-systems test
   hooks only after the parity matrix is green. o1js then depends on mina-rust's
   NAPI/WASM packages as its sole Mina/Pickles backend.

The first implementation target is milestones 1 and 2 together, with a native
Rust integration test that creates a Ledger, compiles a minimal recursive
program, proves it, verifies it, and round-trips every returned artifact before
any NAPI or WASM code is introduced.

Milestones 1 and 2 are implemented on `pickle-rs` in the `mina-runtime` crate.
The crate provides a transport-independent resource store and a versioned JSON
dispatcher shared by future NAPI and WASM bindings. Its v1 contract supports
recorded-circuit registration, real Pickles base proving and standalone
verification, Ledger creation/root/account operations, Mina signed-command
construction/signing, and binprot Base64 encoding. Integration tests generate
and verify a real proof.

The v1 proof contract also supports the first regular recursive slice used by
o1js: `proveCircuitKeep` stores a full base proof behind an opaque process-local
handle, `proveCircuitN1Over` verifies that proof in a new recorded step, and
`verifyRecursiveProof` verifies the serialized N1 result with its step VK and
bulletproof challenge metadata. `dropProof` explicitly releases the retained
base proof. The release integration test exercises keep → N1 → standalone
verification with real Pickles proofs. A serialized proof remains verifiable,
but extending a chain after process loss is not supported until the retained
base handle has a stable import/export format.

Milestone 3 is implemented in `mina-runtime-napi`. The NAPI layer is deliberately
thin: it owns no protocol types and forwards the exact v1 JSON contract to the
core adapter. Lightweight requests can run synchronously, while proving,
verification, and Ledger work use the Node worker pool and accept an
`AbortSignal`. The Node smoke test validates version negotiation, synchronous
and concurrent asynchronous requests, a real Pickles proof, and cancellation of
queued proving work.

Milestone 4 is implemented in `mina-runtime-wasm`. It exposes the same backend
information and `execute` contract through `wasm-bindgen`, without translating
requests or responses. Unit tests compare byte-for-byte responses from the WASM
façade and the core dispatcher for version queries, structured errors, and a
deterministic recorded-circuit compilation fixture. A real
`wasm32-unknown-unknown` artifact builds with nightly and
`-Z build-std=std,panic_abort`, which is required by this workspace's existing
shared-memory and atomics configuration. Heavy calls must execute in an o1js Web
Worker; JavaScript owns scheduling and cancellation so the browser UI thread is
never blocked. The next implementation target is the o1js backend switch from
milestone 5.

_For detailed architecture documentation, see
[`docs/handover/`](docs/handover/)_

## Architecture Overview

### State Machine Pattern

The codebase follows Redux principles:

- **State** - Centralized, immutable data structure
- **Actions** - Events that trigger state changes
- **Enabling Conditions** - Guards that prevent invalid state transitions
- **Reducers** - Functions that update state and dispatch new actions
- **Effects** - Thin wrappers for service calls
- **Services** - Separate threads handling I/O and heavy computation

### Architecture Styles

- **New Style**: Unified reducers that handle both state updates and action
  dispatch
- **Old Style**: Separate reducer and effects files (being migrated)

## Project Structure

### Core Components

**node/** - Main node logic

- `block_producer/` - Block production
- `transaction_pool/` - Transaction mempool
- `transition_frontier/` - Consensus and blockchain state
- `snark_pool/` - SNARK work management
- `ledger/` - Ledger operations
- `rpc/` - External API
- `event_source/` - Event routing
- `service/` - Service implementations

**p2p/** - Networking layer

- Dual transport: libp2p and WebRTC
- Channel abstractions for message types
- Peer discovery and connection management

**snark/** - Proof verification orchestration

**ledger/** - Ledger implementation, transaction logic, core transaction pool
logic, staged ledger, scan state, and proof verification

**core/** - Shared types and utilities

## Code Organization

### File Patterns

- `*_state.rs` - State definitions
- `*_actions.rs` - Action types
- `*_reducer.rs` - State transitions
- `*_effects.rs` - Service interactions
- `*_service.rs` - Service interfaces
- `summary.md` - Component documentation and technical debt notes

### Key Files

- `node/src/state.rs` - Global state structure
- `node/src/action.rs` - Top-level action enum
- `node/src/reducer.rs` - Main reducer dispatch

## Understanding the Flow

1. **Actions** flow through the system as events
2. **Enabling conditions** check if actions are valid
3. **Reducers** process actions to update state
4. **Effects** trigger service calls when needed
5. **Services** handle async operations and send events back

## Key Patterns

### Defensive Programming

- `bug_condition!` macro marks theoretically unreachable code paths
- Used after enabling condition checks for invariant validation

### State Methods

- Complex logic extracted from reducers into state methods
- Keeps reducers focused on orchestration

### Callbacks

- Enable decoupled component communication
- Used for async operation completion

## Finding Code

```bash
# Find specific actions
rg "YourAction" --type rust

# Find reducers
rg "reducer.*Substate" --type rust

# Find services
rg "impl.*Service" --type rust

# Check component documentation
find . -name "summary.md" -path "*/component/*"
```

## Component Documentation

Each component directory contains a `summary.md` file documenting:

- Component purpose and responsibilities
- Known technical debt
- Implementation notes
- Refactoring plans

## Documentation Website

Mina includes a comprehensive documentation website built with Docusaurus:

### Quick Access

```bash
# Start local documentation server
make docs-serve

# Build documentation
make docs-build

# Other documentation commands
make help | grep docs
```

The website is available at http://localhost:3000 when running locally.

### Structure

- **Node Runners** (`website/docs/node-runners/`) - Installation and operation
  guides
- **Developers** (`website/docs/developers/`) - Architecture and contribution
  guides
- **Researchers** (`website/docs/researchers/`) - Protocol and cryptography
  documentation

### Adding Documentation

1. Create markdown files in the appropriate `website/docs/` subdirectory
2. Add frontmatter with title, description, and sidebar position
3. Update `website/sidebars.ts` if needed for navigation

The website supports versioning and will be automatically deployed when commits
are made to `develop` or when tags are created.

### OCaml Reference Tracking

The Rust codebase maintains references to the corresponding OCaml implementation
to track correspondence and detect when updates are needed.

**Comment format:**

```rust
/// OCaml: <https://github.com/MinaProtocol/mina/blob/5da42ccd72e791f164d4d200cf1ce300262873b3/src/lib/mina_base/transaction_status.ml#L9-L51>
pub enum TransactionFailure {
    // ...
}
```

**Validation:**

```bash
# Check all OCaml references
./.github/scripts/check-ocaml-refs.sh

# Update stale commit hashes
./.github/scripts/check-ocaml-refs.sh --update

# Check against specific branch
./.github/scripts/check-ocaml-refs.sh --branch develop
```

The validation script verifies that referenced OCaml files exist, line ranges
are valid, code at the referenced commit matches the current branch, and tracks
commit staleness. A GitHub Actions workflow runs weekly to automatically update
references and create PRs.

## Additional Resources

- `docs/handover/` - Comprehensive architecture documentation
- `ARCHITECTURE.md` - Migration guide for old vs new style
- Component-specific `summary.md` files throughout the codebase
- `website/` - Docusaurus documentation website

## Claude Development Guidelines

This section contains specific instructions for Claude when working on this
project.

### Formatting Commands

After making any code modifications, run the appropriate formatting commands:

#### Markdown and MDX Files

- **Format**: Run `make format-md` after modifying any markdown (.md) or MDX
  (.mdx) files
- **Check**: Run `make check-md` to verify markdown and MDX files are formatted
  correctly

#### Rust and TOML Files

- **Format**: Run `make format` after modifying any Rust (.rs) or TOML (.toml)
  files
- **Check**: Run `make check-format` to verify Rust and TOML files are formatted
  correctly

### Commit Guidelines

**NEVER** add Claude as a co-author in commit messages. Do not include:

- `Co-Authored-By: Claude <noreply@anthropic.com>`
- Any other co-author attribution for Claude

**NEVER** use emojis in commit messages.

**Always** wrap commit message titles at 80 characters and body text at 80
characters.

Always verify commit messages before committing and remove any co-author lines
referencing Claude.

### Development Workflow

1. Make your code changes
2. Run the appropriate formatting command based on file types modified
3. **ALWAYS run `make fix-trailing-whitespace` before committing or ending any
   task**
4. Verify formatting with check commands if needed
5. **Verify commit message does not include Claude as co-author**
6. **Verify commit message contains no emojis and follows 80-character wrap**
7. Proceed with testing or committing changes

### Documentation Script Display

When adding scripts to documentation, always use Docusaurus CodeBlock imports:

```mdx
import CodeBlock from "@theme/CodeBlock";
import ScriptName from "!!raw-loader!./path/to/script.sh";

<CodeBlock language="bash" title="path/to/script.sh">
  {ScriptName}
</CodeBlock>
```

This ensures scripts are displayed accurately and stay in sync with the actual
files.

### Documentation Style Guidelines

**Capitalization in headings and bullet points:**

- Use lowercase for section headings (e.g., "Test design", "Resource
  management")
- Use lowercase for bullet point labels (e.g., "**Connection policies**",
  "**State inspection**")
- Maintain proper capitalization for proper nouns and technical terms
- Apply this style consistently across all documentation files

**Docusaurus admonitions (:::note, :::caution, :::info, etc.):**

- Always wrap Docusaurus admonitions with `<!-- prettier-ignore-start -->` and
  `<!-- prettier-ignore-stop -->` comments
- This prevents prettier from reformatting the admonition blocks
- Example:

  ```mdx
  <!-- prettier-ignore-start -->

  :::note Content of the note here :::

  <!-- prettier-ignore-stop -->
  ```

### Documentation Script Testing

When modifying developer setup scripts in `website/docs/developers/scripts/`,
always test them using the documentation testing workflow:

#### Testing Documentation Scripts

The project includes automated testing of developer setup scripts to ensure they
work correctly across different platforms. This prevents developers from
encountering broken installation instructions.

**When to test:**

- After modifying any script in `website/docs/developers/scripts/setup/`
- When adding new dependencies or tools to the setup process
- When changing installation procedures
- When adding support for a new distribution or platform

**How to trigger tests:**

1. **For PRs**: Add the `test-doc-scripts` label to your pull request
2. **Manual testing**: Use GitHub CLI:
   `gh pr edit <PR_NUMBER> --add-label test-doc-scripts`
3. **Remove and re-add**: If tests need to be re-run, remove the label first:
   ```bash
   gh pr edit <PR_NUMBER> --remove-label test-doc-scripts
   gh pr edit <PR_NUMBER> --add-label test-doc-scripts
   ```

**What gets tested:**

- System dependencies installation (Ubuntu/macOS)
- Rust toolchain setup (including taplo, wasm-pack, etc.)
- Node.js installation
- Docker installation
- Build processes and formatting tools
- Tool version verification

**Why this matters:**

- Ensures documentation stays current with actual requirements
- Prevents "command not found" errors for new developers
- Tests across multiple platforms (Ubuntu 22.04, 24.04, macOS)
- Catches environment drift and dependency changes
- Runs nightly to detect breaking changes early

The tests are designed to run on-demand via labels to avoid slowing down regular
development workflow, as they can take significant time to complete.

### CHANGELOG Guidelines

When making significant changes that affect users or developers, update the
CHANGELOG.md file:

#### CHANGELOG Structure

The CHANGELOG follows [Keep a Changelog](https://keepachangelog.com/) format
with these sections under `## [Unreleased]`:

- **OCaml node** - Changes related to OCaml node compatibility
- **Added** - New features and functionality
- **Changed** - Changes to existing functionality
- **Fixed** - Bug fixes
- **Dependencies** - Dependency updates

#### Entry Format

- Use this format: `- **Category**: Description ([#PR](github-link))`
- Wrap entries at 80 characters with proper indentation
- Categories include: CI, Build System, Documentation, Development Tools, etc.
- Always reference the PR number

#### CHANGELOG Commit Pattern

- Commit message: `CHANGELOG: add entry for patch XXXX`
- Where XXXX is the PR number
- Keep the commit message simple and consistent with existing pattern

Example entry:

```markdown
- **CI**: Generalized build jobs to support multiple platforms (Ubuntu 22.04,
  Ubuntu 24.04, Ubuntu 24.04 ARM, macOS latest) and updated test execution to
  ubuntu-latest ([#1249](https://github.com/o1-labs/openmina/pull/1249))
```

### CI Optimization Guidelines

When modifying CI workflows, especially for performance improvements:

#### Build Job Dependencies

- **Separate "builds for tests" from "builds for verification"**: Create
  dedicated single-platform build jobs that produce only the artifacts needed
  for testing. This allows tests to start as soon as required artifacts are
  available, not waiting for all cross-platform builds to complete.

- **Use selective dependencies**: Instead of depending on matrix build jobs
  (which include all platforms), create specific build jobs that tests can
  depend on. For example:

  ```yaml
  # Before: Tests wait for all platforms
  needs: [build, build-tests]  # Matrix across 7 platforms

  # After: Tests wait for specific artifact-producing builds
  needs: [build-for-tests, build-tests-for-tests]  # Single platform
  ```

- **Maintain cross-platform coverage**: Keep matrix builds for platform
  verification but don't let them block test execution. They should run in
  parallel for verification purposes.

- **Artifact consistency**: Ensure dedicated build jobs produce the same
  artifact names that test jobs expect. Use patterns like
  `bin-${{ github.sha }}` and `tests-${{ github.sha }}` consistently.

#### Performance Considerations

- Tests typically only need artifacts from ubuntu-22.04 builds (for container
  compatibility)
- macOS builds often take longest and shouldn't block Linux-based test execution
- Use ubuntu-22.04 for artifact production to ensure GLIBC compatibility with
  Debian-based test containers

### Critical Pre-Commit Requirements

- **MANDATORY**: Run `make fix-trailing-whitespace` before every commit
- **MANDATORY**: Run `make check-trailing-whitespace` to verify no trailing
  whitespaces remain
- This applies to ALL file modifications, regardless of file type
- Trailing whitespaces are strictly prohibited in the codebase
