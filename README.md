# Tessera

**Temporal Data Sovereignty with Pluggable Storage Backends**

<p align="center">
  <img src="https://media2.giphy.com/media/ckebyFUgKNQMYP7Q8S/giphy.gif" alt="Time flows" width="200"/>
  &nbsp;&nbsp;&nbsp;
  <img src="https://media3.giphy.com/media/077i6AULCXc0FKTj9s/giphy.gif" alt="Data Security" width="200"/>
</p>

Tessera is an Elixir implementation exploring the Ephemeral Consensus Pods (ECP) architecture - enabling control over *when* data is accessible, not merely *to whom*.

## Vision

Modern data systems treat access control as binary: you either have permission or you don't. Tessera introduces **temporal rights** - time-bounded access windows that create "geological strata" of data accessibility, where each temporal layer maintains its own cryptographic access boundaries.

## Core Concepts

### Temporal Rights Algebra

Tessera implements a formal algebra for data permissions:

| Operator | Description |
|----------|-------------|
| `Grant(user, interval)` | Issue time-bounded access rights |
| `Revoke(user, t)` | Terminate forward access at timestamp t |
| `Extend(user, new_interval)` | Prolong existing grant |
| `Freeze(interval)` | Create immutable snapshot |
| `Scope(rights)` | Constrain access type (read-only, compute-only) |
| `Slice(interval)` | Retrieve temporal layer for audit |

### Pluggable Storage Backends

Tessera abstracts data storage behind a unified interface, supporting multiple backends:

- **Solid Pods** - W3C standard personal data stores (Inrupt ESS)
- **ATProto PDS** - Bluesky's Personal Data Servers
- **Memory** - In-memory store for testing/development
- **Custom** - Implement the `Tessera.Store` behaviour

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
├─────────────────────────────────────────────────────────────┤
│                  Tessera.Core.Rights                         │
│         (Temporal Rights Algebra & Grant Management)         │
├─────────────────────────────────────────────────────────────┤
│                  Tessera.Temporal                            │
│            (Time-locks, VDFs, Epoch Management)              │
├─────────────────────────────────────────────────────────────┤
│                  Tessera.Crypto                              │
│      (Key Derivation, Encryption, ZK Proof Foundations)      │
├─────────────────────────────────────────────────────────────┤
│                  Tessera.Store (Behaviour)                   │
├──────────────┬──────────────┬──────────────┬────────────────┤
│  Solid Pod   │   ATProto    │    Memory    │    Custom      │
│   Adapter    │   Adapter    │   Adapter    │   Adapter      │
└──────────────┴──────────────┴──────────────┴────────────────┘
```

## Project Structure

```
lib/tessera/
├── core/
│   ├── rights/          # Temporal rights algebra implementation
│   └── grants/          # Grant lifecycle management
├── stores/
│   ├── store.ex         # Store behaviour definition
│   ├── solid/           # Solid Pod adapter
│   ├── atproto/         # ATProto PDS adapter
│   └── memory/          # In-memory adapter
├── temporal/            # Time-lock primitives, VDFs, epochs
├── crypto/              # Cryptographic primitives
└── protocols/           # Wire protocols, attestation formats
```

## Getting Started

```bash
# Clone the repository
git clone https://github.com/justin4957/tessera.git
cd tessera

# Install dependencies
mix deps.get

# Run tests
mix test

# Start interactive shell
iex -S mix
```

## Storage Backend Quick Start

Tessera supports multiple storage backends. See [Storage Backends Guide](docs/STORAGE_BACKENDS.md) for full documentation.

### Memory (Development/Testing)

```elixir
{:ok, _} = Tessera.Stores.Memory.Adapter.start_link(name: :store)

:ok = Tessera.Stores.Memory.Adapter.put("my-key", %{data: "value"}, %{}, :store)
{:ok, data, _meta} = Tessera.Stores.Memory.Adapter.get("my-key", :store)
```

### ATProto (Bluesky PDS)

```elixir
{:ok, _} = Tessera.Stores.ATProto.Adapter.start_link(
  name: :atproto,
  pds_url: "https://bsky.social",
  identifier: "your-handle.bsky.social",
  password: "your-app-password",
  collection: "app.tessera.record"
)

:ok = Tessera.Stores.ATProto.Adapter.put("doc-1", %{title: "Hello"}, %{}, :atproto)
{:ok, data, _meta} = Tessera.Stores.ATProto.Adapter.get("doc-1", :atproto)
```

### Solid Pod

```elixir
{:ok, _} = Tessera.Stores.Solid.Adapter.start_link(
  name: :solid,
  pod_url: "https://storage.inrupt.com/your-pod-id/",
  credentials: %{id: "client-id", secret: "client-secret"}
)

:ok = Tessera.Stores.Solid.Adapter.put("docs/report", %{year: 2024}, %{}, :solid)
{:ok, data, _meta} = Tessera.Stores.Solid.Adapter.get("docs/report", :solid)
```

## Example Usage

```elixir
# Create a temporal grant
alias Tessera.Core.{Grants.Grant, Rights.TemporalInterval}

# Grant read access for 30 days
grant = Grant.new(
  grantee_id: "did:web:alice.example",
  resource_id: "data/medical/records",
  interval: TemporalInterval.for_duration(30, :day),
  scope: [:read],
  purpose: "insurance_claim_2024"
)

# Check if grant is currently active
Grant.active?(grant)  # => true

# Revoke forward access (historical access remains provable)
{:ok, revoked_grant} = Grant.revoke(grant)

# Freeze for immutable audit snapshot
{:ok, frozen_grant} = Grant.freeze(grant)
```

## Roadmap

### Phase 1: Core Data Layer
- [x] Store behaviour and memory adapter
- [x] Basic temporal rights algebra
- [x] Grant/revoke primitives

### Phase 2: Real Storage Backends (Current)
- [x] ATProto PDS integration ([#1](https://github.com/justin4957/tessera/issues/1))
- [x] Solid Pod integration ([#2](https://github.com/justin4957/tessera/issues/2))

### Phase 3: Cryptographic Foundations
- [ ] Hierarchical key derivation ([#8](https://github.com/justin4957/tessera/issues/8))
- [ ] Epoch-based key rotation ([#9](https://github.com/justin4957/tessera/issues/9))
- [ ] Time-lock encryption primitives ([#10](https://github.com/justin4957/tessera/issues/10))

### Phase 4: Distributed Consensus
- [ ] ZK participation proofs ([#11](https://github.com/justin4957/tessera/issues/11))
- [ ] Blockchain attestation integration ([#12](https://github.com/justin4957/tessera/issues/12))

## Documentation

- [Storage Backends Guide](docs/STORAGE_BACKENDS.md) - Configuration and usage for all storage adapters
- [ECP Implementation Roadmap](docs/ECP_Implementation_Roadmap.docx) - Full architectural vision

## Inspiration

This project explores concepts from the Ephemeral Consensus Pods (ECP) architecture, synthesizing:

- Personal data sovereignty (Solid, ATProto)
- Blockchain-based temporal attestation
- Cryptographically-enforced access windows
- Verifiable absence proofs

## Contributing

Contributions welcome! This is an experimental/MVP implementation exploring novel data sovereignty patterns.

## License

MIT
