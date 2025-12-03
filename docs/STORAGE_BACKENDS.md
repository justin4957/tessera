# Storage Backends Configuration Guide

Tessera supports multiple storage backends through its pluggable `Tessera.Store` behaviour. This guide covers configuration and usage for each supported backend.

## Table of Contents

- [Store Behaviour](#store-behaviour)
- [Memory Adapter](#memory-adapter)
- [ATProto PDS Adapter](#atproto-pds-adapter)
- [Solid Pod Adapter](#solid-pod-adapter)
- [Implementing Custom Adapters](#implementing-custom-adapters)

---

## Store Behaviour

All storage adapters implement the `Tessera.Store` behaviour, providing a unified interface:

```elixir
# Core operations
put(resource_id, data, metadata)     # Store data
get(resource_id)                      # Retrieve data
delete(resource_id)                   # Remove data
list(prefix \\ nil)                   # List resources
exists?(resource_id)                  # Check existence

# Connection management
connect(opts)                         # Establish connection
disconnect()                          # Close connection
info()                                # Get adapter metadata
```

---

## Memory Adapter

The in-memory adapter is ideal for testing and development.

### Configuration

No configuration required - works out of the box.

### Usage

```elixir
# Start the memory adapter
{:ok, pid} = Tessera.Stores.Memory.Adapter.start_link(name: :my_store)

# Store data
:ok = Tessera.Stores.Memory.Adapter.put(
  "users/alice",
  %{name: "Alice", email: "alice@example.com"},
  %{},
  :my_store
)

# Retrieve data
{:ok, data, metadata} = Tessera.Stores.Memory.Adapter.get("users/alice", :my_store)

# List all resources
{:ok, resource_ids} = Tessera.Stores.Memory.Adapter.list(nil, :my_store)

# List with prefix filter
{:ok, user_ids} = Tessera.Stores.Memory.Adapter.list("users/", :my_store)

# Check existence
true = Tessera.Stores.Memory.Adapter.exists?("users/alice", :my_store)

# Delete
:ok = Tessera.Stores.Memory.Adapter.delete("users/alice", :my_store)
```

---

## ATProto PDS Adapter

Connect to Bluesky's AT Protocol Personal Data Servers.

### Prerequisites

1. An ATProto account (Bluesky or self-hosted PDS)
2. Your DID (Decentralized Identifier)
3. App password or account credentials

### Configuration

#### Environment Variables

```bash
export ATPROTO_PDS_URL="https://bsky.social"
export ATPROTO_IDENTIFIER="your-handle.bsky.social"
export ATPROTO_PASSWORD="your-app-password"
```

#### Application Config

```elixir
# config/config.exs
config :tessera, Tessera.Stores.ATProto.Adapter,
  pds_url: System.get_env("ATPROTO_PDS_URL"),
  identifier: System.get_env("ATPROTO_IDENTIFIER"),
  password: System.get_env("ATPROTO_PASSWORD"),
  collection: "app.tessera.record"  # NSID for your records
```

### Usage

#### Starting with Auto-Connect

```elixir
# Credentials provided at start - auto-connects
{:ok, pid} = Tessera.Stores.ATProto.Adapter.start_link(
  name: :atproto_store,
  pds_url: "https://bsky.social",
  identifier: "alice.bsky.social",
  password: "app-password-here",
  collection: "app.tessera.record"
)

# Check connection status
info = Tessera.Stores.ATProto.Adapter.info(:atproto_store)
# => %{type: :atproto, connected: true, did: "did:plc:...", ...}
```

#### Deferred Authentication

```elixir
# Start without credentials
{:ok, pid} = Tessera.Stores.ATProto.Adapter.start_link(
  name: :atproto_store,
  pds_url: "https://bsky.social",
  collection: "app.tessera.record"
)

# Connect later when credentials available
:ok = Tessera.Stores.ATProto.Adapter.connect(
  [
    identifier: "alice.bsky.social",
    password: "app-password-here"
  ],
  :atproto_store
)
```

#### CRUD Operations

```elixir
alias Tessera.Stores.ATProto.Adapter, as: ATProto

# Store a record
:ok = ATProto.put(
  "my-resource-key",
  %{
    "title" => "My Document",
    "content" => "Hello, ATProto!",
    "tags" => ["tessera", "demo"]
  },
  %{},
  :atproto_store
)

# Retrieve the record
{:ok, data, metadata} = ATProto.get("my-resource-key", :atproto_store)
# data => %{"title" => "My Document", ...}
# metadata => %{created_at: ~U[...], cid: "bafyrei...", uri: "at://..."}

# List all records in the collection
{:ok, keys} = ATProto.list(nil, :atproto_store)
# => ["my-resource-key", "another-key", ...]

# Check if record exists
true = ATProto.exists?("my-resource-key", :atproto_store)

# Delete a record
:ok = ATProto.delete("my-resource-key", :atproto_store)
```

### ATProto-Specific Features

#### Custom Collections

ATProto organizes data into collections identified by NSIDs (Namespaced Identifiers):

```elixir
# Different collections for different data types
{:ok, _} = Tessera.Stores.ATProto.Adapter.start_link(
  name: :user_profiles,
  pds_url: "https://bsky.social",
  identifier: "alice.bsky.social",
  password: "password",
  collection: "app.tessera.profile"
)

{:ok, _} = Tessera.Stores.ATProto.Adapter.start_link(
  name: :documents,
  pds_url: "https://bsky.social",
  identifier: "alice.bsky.social",
  password: "password",
  collection: "app.tessera.document"
)
```

#### Session Management

The adapter automatically handles session refresh:

```elixir
# Sessions are refreshed automatically when expired
# You can also manually disconnect/reconnect
:ok = ATProto.disconnect(:atproto_store)
:ok = ATProto.connect([identifier: "...", password: "..."], :atproto_store)
```

### Getting App Passwords

For Bluesky accounts:
1. Go to Settings > App Passwords
2. Create a new app password
3. Use this password instead of your main account password

---

## Solid Pod Adapter

Connect to W3C Solid Protocol personal data stores.

### Prerequisites

1. A Solid Pod (Inrupt PodSpaces, Community Solid Server, etc.)
2. Client credentials (ID and Secret) from your identity provider

### Obtaining Client Credentials

#### Inrupt PodSpaces / ESS

1. Log into your Pod provider's dashboard
2. Navigate to "Preferences" or "Developer Settings"
3. Generate new client credentials
4. Note the Client ID and Client Secret

#### Community Solid Server (CSS)

```bash
# Generate credentials via the IDP endpoint
curl -X POST https://your-css-server/idp/credentials/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "your-email@example.com",
    "password": "your-password",
    "name": "tessera-client"
  }'

# Response:
# {"id": "client-id-here", "secret": "client-secret-here"}
```

### Configuration

#### Environment Variables

```bash
export SOLID_POD_URL="https://storage.inrupt.com/your-pod-id/"
export SOLID_CLIENT_ID="your-client-id"
export SOLID_CLIENT_SECRET="your-client-secret"
```

#### Application Config

```elixir
# config/config.exs
config :tessera, Tessera.Stores.Solid.Adapter,
  pod_url: System.get_env("SOLID_POD_URL"),
  credentials: %{
    id: System.get_env("SOLID_CLIENT_ID"),
    secret: System.get_env("SOLID_CLIENT_SECRET")
  },
  base_path: "tessera/"  # Optional: customize storage location
```

### Usage

#### Starting with Auto-Connect

```elixir
# Credentials provided at start - auto-connects
{:ok, pid} = Tessera.Stores.Solid.Adapter.start_link(
  name: :solid_store,
  pod_url: "https://storage.inrupt.com/abc123/",
  credentials: %{
    id: "your-client-id",
    secret: "your-client-secret"
  }
)

# Check connection status
info = Tessera.Stores.Solid.Adapter.info(:solid_store)
# => %{type: :solid, connected: true, pod_url: "...", webid: "...", ...}
```

#### Deferred Authentication

```elixir
# Start without credentials
{:ok, pid} = Tessera.Stores.Solid.Adapter.start_link(
  name: :solid_store,
  pod_url: "https://storage.inrupt.com/abc123/"
)

# Connect later
:ok = Tessera.Stores.Solid.Adapter.connect(
  [
    credentials: %{id: "client-id", secret: "client-secret"}
  ],
  :solid_store
)
```

#### Password-Based Authentication (Development Only)

For development/testing with Community Solid Server:

```elixir
alias Tessera.Stores.Solid.Client

# Create session with email/password (generates credentials automatically)
{:ok, session} = Client.create_session_with_password(
  "https://pod.example.com/alice/",
  "https://pod.example.com",  # IDP URL
  "alice@example.com",
  "password123"
)
```

#### CRUD Operations

```elixir
alias Tessera.Stores.Solid.Adapter, as: Solid

# Store data (automatically creates containers)
:ok = Solid.put(
  "documents/report-2024",
  %{
    "title" => "Annual Report",
    "year" => 2024,
    "sections" => ["intro", "analysis", "conclusion"]
  },
  %{},
  :solid_store
)

# Retrieve data
{:ok, data, metadata} = Solid.get("documents/report-2024", :solid_store)
# data => %{"title" => "Annual Report", ...}
# metadata => %{created_at: ~U[...], etag: "\"abc123\"", ...}

# List all resources
{:ok, resource_ids} = Solid.list(nil, :solid_store)
# => ["documents/report-2024", "users/profile", ...]

# List with prefix filter
{:ok, doc_ids} = Solid.list("documents", :solid_store)
# => ["documents/report-2024", "documents/notes"]

# Check existence
true = Solid.exists?("documents/report-2024", :solid_store)

# Delete
:ok = Solid.delete("documents/report-2024", :solid_store)
```

### Solid-Specific Features

#### Container Management

The adapter automatically creates container hierarchies:

```elixir
# This automatically creates:
# - /tessera/
# - /tessera/projects/
# - /tessera/projects/alpha/
# And stores the file at:
# - /tessera/projects/alpha/data.json
:ok = Solid.put("projects/alpha/data", %{name: "Alpha"}, %{}, :solid_store)
```

#### Custom Base Path

Store Tessera data in a custom location within your Pod:

```elixir
{:ok, _} = Tessera.Stores.Solid.Adapter.start_link(
  name: :solid_store,
  pod_url: "https://pod.example.com/alice/",
  credentials: %{id: "...", secret: "..."},
  base_path: "apps/tessera/data/"  # Custom path
)
```

#### ETag Support for Optimistic Concurrency

The metadata returned includes ETags for conflict detection:

```elixir
{:ok, data, metadata} = Solid.get("my-resource", :solid_store)
etag = metadata.etag  # => "\"abc123\""

# Use ETag for conditional updates (via Client directly)
alias Tessera.Stores.Solid.Client

# Only update if unchanged
{:ok, _} = Client.put_resource(
  session,
  "tessera/my-resource.json",
  Jason.encode!(%{data: "updated"}),
  content_type: "application/json",
  if_match: etag
)
```

### Solid Pod Providers

| Provider | URL | Notes |
|----------|-----|-------|
| Inrupt PodSpaces | https://start.inrupt.com | Enterprise-grade, free tier available |
| solidcommunity.net | https://solidcommunity.net | Community-run, open registration |
| Self-hosted CSS | - | Run your own Community Solid Server |

---

## Implementing Custom Adapters

Create your own storage backend by implementing `Tessera.Store`:

```elixir
defmodule MyApp.Stores.CustomAdapter do
  use GenServer
  @behaviour Tessera.Store

  # Required callbacks
  @impl Tessera.Store
  def put(resource_id, data, metadata, server \\ __MODULE__) do
    GenServer.call(server, {:put, resource_id, data, metadata})
  end

  @impl Tessera.Store
  def get(resource_id, server \\ __MODULE__) do
    GenServer.call(server, {:get, resource_id})
  end

  @impl Tessera.Store
  def delete(resource_id, server \\ __MODULE__) do
    GenServer.call(server, {:delete, resource_id})
  end

  @impl Tessera.Store
  def list(prefix \\ nil, server \\ __MODULE__) do
    GenServer.call(server, {:list, prefix})
  end

  @impl Tessera.Store
  def exists?(resource_id, server \\ __MODULE__) do
    GenServer.call(server, {:exists?, resource_id})
  end

  @impl Tessera.Store
  def info(server \\ __MODULE__) do
    GenServer.call(server, :info)
  end

  @impl Tessera.Store
  def connect(opts, server \\ __MODULE__) do
    GenServer.call(server, {:connect, opts})
  end

  @impl Tessera.Store
  def disconnect(server \\ __MODULE__) do
    GenServer.call(server, :disconnect)
  end

  # GenServer implementation...
end
```

### Return Value Conventions

| Function | Success | Not Found | Error |
|----------|---------|-----------|-------|
| `put/4` | `:ok` | N/A | `{:error, reason}` |
| `get/2` | `{:ok, data, metadata}` | `{:error, :not_found}` | `{:error, reason}` |
| `delete/2` | `:ok` | `{:error, :not_found}` | `{:error, reason}` |
| `list/2` | `{:ok, [resource_ids]}` | `{:ok, []}` | `{:error, reason}` |
| `exists?/2` | `true` | `false` | `false` |
| `info/1` | `%{type: atom, ...}` | N/A | N/A |
| `connect/2` | `:ok` | N/A | `{:error, reason}` |
| `disconnect/1` | `:ok` | N/A | N/A |

---

## Testing with Mox

Both ATProto and Solid adapters use a mockable HTTP client for testing:

```elixir
# test/test_helper.exs
Mox.defmock(Tessera.MockHTTPClient, for: Tessera.HTTPClientBehaviour)

# config/test.exs
config :tessera, :http_client, Tessera.MockHTTPClient

# In your tests
import Mox

setup :verify_on_exit!

test "stores data successfully" do
  Tessera.MockHTTPClient
  |> expect(:post, fn _url, _opts -> {:ok, %{status: 200, body: %{}, headers: []}} end)
  |> expect(:put, fn _url, _opts -> {:ok, %{status: 201, body: "", headers: []}} end)

  # Your test code...
end
```

---

## Troubleshooting

### ATProto

**"Invalid identifier or password"**
- Ensure you're using an app password, not your main password
- Verify the handle format (e.g., `alice.bsky.social`)

**"Rate limited"**
- ATProto PDS servers have rate limits
- Implement exponential backoff for bulk operations

### Solid

**"Unauthorized" errors**
- Client credentials may have expired - regenerate them
- Ensure credentials have write permissions to the Pod

**"Container not found"**
- The adapter auto-creates containers, but check Pod permissions
- Verify the base_path doesn't conflict with existing resources

**OIDC Discovery fails**
- Some servers use non-standard token endpoints
- Specify `token_endpoint` explicitly in options

---

## Further Reading

- [ATProto Documentation](https://atproto.com/docs)
- [Solid Protocol Specification](https://solidproject.org/TR/protocol)
- [Tessera Store Behaviour](../lib/tessera/stores/store.ex)
