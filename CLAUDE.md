# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

```bash
# Install dependencies
mix deps.get

# Run all tests
mix test

# Run a specific test file
mix test test/tessera/crypto/zk_test.exs

# Run a specific test by line number
mix test test/tessera/crypto/zk_test.exs:42

# Start interactive shell
iex -S mix

# Format code (required before PRs)
mix format

# Check formatting
mix format --check-formatted
```

## Architecture

Tessera implements the Ephemeral Consensus Pods (ECP) architecture for temporal data sovereignty - controlling *when* data is accessible via time-bounded cryptographic access.

### Layer Structure

```
┌─────────────────────────────────────────────────────┐
│              Tessera.Core.Rights                     │
│      (Temporal rights algebra, grants/revoke)        │
├─────────────────────────────────────────────────────┤
│              Tessera.Crypto                          │
│   (Key derivation, epochs, time-locks, ZK proofs)   │
├─────────────────────────────────────────────────────┤
│              Tessera.Store (Behaviour)               │
├───────────────┬───────────────┬─────────────────────┤
│  Solid Pod    │   ATProto     │    Memory           │
│   Adapter     │   Adapter     │   Adapter           │
└───────────────┴───────────────┴─────────────────────┘
```

### Key Modules

- **`Tessera.Store`** (`lib/tessera/stores/store.ex`): Behaviour defining pluggable storage backend interface. All adapters implement: `put/3`, `get/1`, `delete/1`, `list/1`, `exists?/1`, `info/0`, `connect/1`, `disconnect/0`.

- **`Tessera.Core.Grants.Grant`**: Temporal grant lifecycle - creation, revocation, freezing. Grants bind users to resources with time-bounded intervals and scoped permissions.

- **`Tessera.Core.Rights.TemporalInterval`**: Time interval algebra for access windows.

- **`Tessera.Crypto.KeyDerivation`**: Hierarchical key derivation (root -> epoch -> conversation -> message keys).

- **`Tessera.Crypto.EpochManager`**: Manages epoch-based key rotation with configurable durations.

- **`Tessera.Crypto.TimeLock` / `TimeLockVault`**: Time-lock encryption primitives using VDFs for future-dated decryption.

- **`Tessera.Crypto.ZK`**: Zero-knowledge proof facade for participation, range, and membership proofs using Pedersen-like commitments with SHA-256.

### Storage Adapters

Each adapter is a GenServer implementing `Tessera.Store`:

- **Memory** (`Tessera.Stores.Memory.Adapter`): In-memory ETS-backed, for testing
- **ATProto** (`Tessera.Stores.ATProto.Adapter`): Bluesky PDS integration
- **Solid** (`Tessera.Stores.Solid.Adapter`): W3C Solid Pod integration

Adapters use a mockable HTTP client (`Tessera.HTTPClientBehaviour`) for testing with Mox.

## Testing

Tests use Mox for HTTP client mocking:

```elixir
# test/test_helper.exs defines:
Mox.defmock(Tessera.MockHTTPClient, for: Tessera.HTTPClientBehaviour)

# config/test.exs configures:
config :tessera, :http_client, Tessera.MockHTTPClient
```

In tests, set up expectations before calling adapter functions:

```elixir
import Mox
setup :verify_on_exit!

Tessera.MockHTTPClient
|> expect(:post, fn _url, _opts -> {:ok, %{status: 200, body: %{}, headers: []}} end)
```

## PR Review Workflow

After creating a PR, use `multi_agent_coder` for comprehensive multi-provider code review:

```bash
# Navigate to multi_agent_coder
cd ../multi_agent_coder

# Run concurrent review with multiple AI providers
./multi_agent_coder -s all -p anthropic,openai,gemini,deepseek \
  "Review PR #<number> in Tessera. Focus on: 1) Security, 2) Elixir best practices, 3) API design."
```

### Review Comment Format

Include in PR comments:
1. **Agent attributions** - Quote each provider's findings with model names
2. **Consensus issues** - Issues identified by multiple agents
3. **Token/cost estimates** - Track usage per provider
4. **Prioritized action items** - CRITICAL/HIGH/MEDIUM/LOW

### Post-PR Checklist

1. `mix format` - Format code
2. `mix format --check-formatted` - Verify formatting
3. `mix test` - Run full test suite
4. `gh pr checks <pr-number>` - Verify CI passes (Code Quality, Test, Build Escript)
