defmodule Tessera.Audit do
  @moduledoc """
  Behaviour defining the interface for audit logging.

  The audit system provides tamper-evident logging of security-relevant events
  in Tessera. All audit entries are hash-chained to provide integrity verification.

  ## Event Types

  - Grant lifecycle: `:grant_created`, `:grant_revoked`, `:grant_frozen`, `:grant_deleted`
  - Data access: `:data_sealed`, `:data_unsealed`, `:access_denied`
  - Key management: `:key_rotated`, `:epoch_boundary`
  - Authentication: `:session_started`, `:session_ended`, `:auth_failed`

  ## Implementations

  - `Tessera.Audit.Memory` - In-memory (ETS) for testing
  - Future: `Tessera.Audit.Persistent` - Disk-based append-only log

  ## Usage

      # Log an event
      {:ok, entry} = Audit.log_event(adapter, :grant_created, %{
        actor_id: "did:web:alice.example",
        resource_id: "pod://data/record",
        grant_id: "grant_123"
      })

      # Query events
      {:ok, events} = Audit.query_events(adapter,
        event_type: :grant_created,
        from: ~U[2024-01-01 00:00:00Z],
        to: ~U[2024-12-31 23:59:59Z]
      )

      # Verify chain integrity
      :ok = Audit.verify_chain(adapter, ~U[2024-01-01 00:00:00Z], ~U[2024-12-31 23:59:59Z])

  ## Hash Chaining

  Each audit entry includes a hash of the previous entry, creating a tamper-evident
  chain. Any modification to historical entries will cause chain verification to fail.

  ```
  Entry N:   [data, hash(Entry N-1)]
  Entry N+1: [data, hash(Entry N)]
  Entry N+2: [data, hash(Entry N+1)]
  ```
  """

  alias Tessera.Audit.Entry

  # Grant lifecycle
  @type event_type ::
          :grant_created
          | :grant_modified
          | :grant_revoked
          | :grant_frozen
          | :grant_deleted
          # Data access
          | :data_sealed
          | :data_unsealed
          | :access_denied
          | :access_granted
          # Key management
          | :key_rotated
          | :epoch_boundary
          | :key_derived
          # Authentication
          | :session_started
          | :session_ended
          | :auth_failed
          | :auth_succeeded

  @type query_opts :: [
          event_type: event_type() | [event_type()],
          actor_id: String.t(),
          resource_id: String.t(),
          from: DateTime.t(),
          to: DateTime.t(),
          limit: pos_integer(),
          offset: non_neg_integer()
        ]

  @type error :: {:error, term()}

  # ============================================================================
  # Callbacks
  # ============================================================================

  @doc """
  Logs an audit event.

  Creates a new audit entry with the specified event type and details.
  The entry is automatically hash-chained to the previous entry.

  ## Returns

  - `{:ok, entry}` - Event logged successfully
  - `{:error, reason}` - Logging failed
  """
  @callback log_event(event_type(), details :: map()) :: {:ok, Entry.t()} | error()

  @doc """
  Queries audit events with optional filters.

  ## Options

  - `:event_type` - Filter by event type (single or list)
  - `:actor_id` - Filter by actor ID
  - `:resource_id` - Filter by resource ID
  - `:from` - Start of time range (inclusive)
  - `:to` - End of time range (inclusive)
  - `:limit` - Maximum number of results
  - `:offset` - Number of results to skip

  ## Returns

  - `{:ok, [entry]}` - List of matching entries (may be empty)
  """
  @callback query_events(query_opts()) :: {:ok, [Entry.t()]} | error()

  @doc """
  Retrieves a specific audit entry by ID.

  ## Returns

  - `{:ok, entry}` - Entry found
  - `{:error, :not_found}` - Entry does not exist
  """
  @callback get_entry(entry_id :: String.t()) :: {:ok, Entry.t()} | {:error, :not_found} | error()

  @doc """
  Verifies the integrity of the audit chain within a time range.

  Checks that all entries in the range have valid hash chains linking
  them together.

  ## Returns

  - `:ok` - Chain is valid
  - `{:error, {:chain_broken, entry_id}}` - Chain integrity violation at entry
  - `{:error, :empty_range}` - No entries in the specified range
  """
  @callback verify_chain(from :: DateTime.t(), to :: DateTime.t()) ::
              :ok | {:error, {:chain_broken, String.t()} | :empty_range} | error()

  @doc """
  Returns the current chain head (most recent entry hash).

  ## Returns

  - `{:ok, hash}` - Current chain head hash
  - `{:ok, nil}` - No entries in the log yet
  """
  @callback chain_head() :: {:ok, binary() | nil} | error()

  @doc """
  Returns information about the audit log.

  ## Returns

  Map containing:
  - `:type` - Adapter type (:memory, :persistent)
  - `:entry_count` - Number of audit entries
  - `:chain_head` - Hash of the most recent entry
  - `:oldest_entry` - Timestamp of oldest entry
  - `:newest_entry` - Timestamp of newest entry
  """
  @callback info() :: map()

  @optional_callbacks []

  # ============================================================================
  # Public API (Delegates to Adapter)
  # ============================================================================

  @doc """
  Logs an audit event using the specified adapter.
  """
  @spec log_event(module(), event_type(), map()) :: {:ok, Entry.t()} | error()
  def log_event(adapter, event_type, details) do
    adapter.log_event(event_type, details)
  end

  @doc """
  Queries audit events using the specified adapter.
  """
  @spec query_events(module(), query_opts()) :: {:ok, [Entry.t()]} | error()
  def query_events(adapter, opts \\ []) do
    adapter.query_events(opts)
  end

  @doc """
  Retrieves a specific audit entry using the specified adapter.
  """
  @spec get_entry(module(), String.t()) :: {:ok, Entry.t()} | error()
  def get_entry(adapter, entry_id) do
    adapter.get_entry(entry_id)
  end

  @doc """
  Verifies chain integrity using the specified adapter.
  """
  @spec verify_chain(module(), DateTime.t(), DateTime.t()) ::
          :ok | {:error, {:chain_broken, String.t()} | :empty_range} | error()
  def verify_chain(adapter, from, to) do
    adapter.verify_chain(from, to)
  end

  @doc """
  Returns the chain head using the specified adapter.
  """
  @spec chain_head(module()) :: {:ok, binary() | nil} | error()
  def chain_head(adapter) do
    adapter.chain_head()
  end

  @doc """
  Returns adapter information.
  """
  @spec info(module()) :: map()
  def info(adapter) do
    adapter.info()
  end

  # ============================================================================
  # Convenience Functions
  # ============================================================================

  @doc """
  Logs a grant creation event.
  """
  @spec log_grant_created(module(), map()) :: {:ok, Entry.t()} | error()
  def log_grant_created(adapter, details) do
    log_event(adapter, :grant_created, details)
  end

  @doc """
  Logs a grant revocation event.
  """
  @spec log_grant_revoked(module(), map()) :: {:ok, Entry.t()} | error()
  def log_grant_revoked(adapter, details) do
    log_event(adapter, :grant_revoked, details)
  end

  @doc """
  Logs a data seal (encryption) event.
  """
  @spec log_data_sealed(module(), map()) :: {:ok, Entry.t()} | error()
  def log_data_sealed(adapter, details) do
    log_event(adapter, :data_sealed, details)
  end

  @doc """
  Logs a data unseal (decryption) event.
  """
  @spec log_data_unsealed(module(), map()) :: {:ok, Entry.t()} | error()
  def log_data_unsealed(adapter, details) do
    log_event(adapter, :data_unsealed, details)
  end

  @doc """
  Logs an access denied event.
  """
  @spec log_access_denied(module(), map()) :: {:ok, Entry.t()} | error()
  def log_access_denied(adapter, details) do
    log_event(adapter, :access_denied, details)
  end

  @doc """
  Logs a key rotation event.
  """
  @spec log_key_rotated(module(), map()) :: {:ok, Entry.t()} | error()
  def log_key_rotated(adapter, details) do
    log_event(adapter, :key_rotated, details)
  end

  @doc """
  Exports audit entries for compliance reporting.

  Returns entries in a format suitable for external audit systems.
  """
  @spec export(module(), query_opts()) :: {:ok, [map()]} | error()
  def export(adapter, opts \\ []) do
    with {:ok, entries} <- query_events(adapter, opts) do
      exported =
        Enum.map(entries, fn entry ->
          %{
            id: entry.id,
            timestamp: DateTime.to_iso8601(entry.timestamp),
            event_type: entry.event_type,
            actor_id: entry.actor_id,
            resource_id: entry.resource_id,
            details: entry.details,
            entry_hash: Base.encode16(entry.entry_hash, case: :lower),
            previous_hash:
              if(entry.previous_hash, do: Base.encode16(entry.previous_hash, case: :lower))
          }
        end)

      {:ok, exported}
    end
  end
end
