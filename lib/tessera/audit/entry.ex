defmodule Tessera.Audit.Entry do
  @moduledoc """
  Represents an immutable audit log entry.

  Each entry contains:
  - Unique identifier
  - Timestamp of when the event occurred
  - Event type classification
  - Actor (who performed the action)
  - Resource (what was acted upon)
  - Details (event-specific metadata)
  - Hash chain references for tamper detection

  ## Hash Chaining

  The `entry_hash` is computed from:
  - `id`
  - `timestamp`
  - `event_type`
  - `actor_id`
  - `resource_id`
  - `details` (sorted, deterministic)
  - `previous_hash`

  This creates a cryptographic chain where any modification to historical
  entries will cause subsequent hashes to become invalid.

  ## Example

      entry = Entry.new(
        event_type: :grant_created,
        actor_id: "did:web:alice.example",
        resource_id: "pod://data/record",
        details: %{grant_id: "g_123", scope: [:read]},
        previous_hash: previous_entry.entry_hash
      )

      # Verify entry hash
      true = Entry.verify_hash(entry)
  """

  @enforce_keys [:id, :timestamp, :event_type, :entry_hash]
  defstruct [
    :id,
    :timestamp,
    :event_type,
    :actor_id,
    :resource_id,
    :details,
    :previous_hash,
    :entry_hash,
    :sequence_number
  ]

  @type t :: %__MODULE__{
          id: String.t(),
          timestamp: DateTime.t(),
          event_type: atom(),
          actor_id: String.t() | nil,
          resource_id: String.t() | nil,
          details: map(),
          previous_hash: binary() | nil,
          entry_hash: binary(),
          sequence_number: non_neg_integer() | nil
        }

  @hash_algorithm :sha256
  @domain_separator "tessera.audit.entry.v1"

  @doc """
  Creates a new audit entry with computed hash.

  ## Options

  - `:event_type` - Type of event (required)
  - `:actor_id` - ID of the actor performing the action
  - `:resource_id` - ID of the resource being acted upon
  - `:details` - Event-specific metadata (default: %{})
  - `:previous_hash` - Hash of the previous entry (nil for first entry)
  - `:sequence_number` - Optional sequence number

  ## Returns

  A new entry struct with computed `entry_hash`.
  """
  @spec new(keyword()) :: t()
  def new(attrs) do
    id = Keyword.get(attrs, :id, generate_id())
    timestamp = Keyword.get(attrs, :timestamp, DateTime.utc_now())
    event_type = Keyword.fetch!(attrs, :event_type)
    actor_id = Keyword.get(attrs, :actor_id)
    resource_id = Keyword.get(attrs, :resource_id)
    details = Keyword.get(attrs, :details, %{})
    previous_hash = Keyword.get(attrs, :previous_hash)
    sequence_number = Keyword.get(attrs, :sequence_number)

    entry_hash =
      compute_hash(id, timestamp, event_type, actor_id, resource_id, details, previous_hash)

    %__MODULE__{
      id: id,
      timestamp: timestamp,
      event_type: event_type,
      actor_id: actor_id,
      resource_id: resource_id,
      details: details,
      previous_hash: previous_hash,
      entry_hash: entry_hash,
      sequence_number: sequence_number
    }
  end

  @doc """
  Verifies that an entry's hash is correct.

  Recomputes the hash from the entry's fields and compares it
  to the stored `entry_hash`.

  ## Returns

  - `true` if the hash is valid
  - `false` if the hash has been tampered with
  """
  @spec verify_hash(t()) :: boolean()
  def verify_hash(%__MODULE__{} = entry) do
    expected_hash =
      compute_hash(
        entry.id,
        entry.timestamp,
        entry.event_type,
        entry.actor_id,
        entry.resource_id,
        entry.details,
        entry.previous_hash
      )

    :crypto.hash_equals(entry.entry_hash, expected_hash)
  end

  @doc """
  Verifies that two entries form a valid chain link.

  Checks that `next_entry.previous_hash` equals `previous_entry.entry_hash`.

  ## Returns

  - `true` if the chain link is valid
  - `false` if the chain is broken
  """
  @spec verify_chain_link(previous :: t(), next :: t()) :: boolean()
  def verify_chain_link(%__MODULE__{} = previous_entry, %__MODULE__{} = next_entry) do
    case next_entry.previous_hash do
      nil -> false
      hash -> :crypto.hash_equals(hash, previous_entry.entry_hash)
    end
  end

  @doc """
  Returns the hash of an entry for use as `previous_hash` in subsequent entries.
  """
  @spec hash(t()) :: binary()
  def hash(%__MODULE__{entry_hash: entry_hash}), do: entry_hash

  @doc """
  Compares two entries by timestamp for sorting.
  """
  @spec compare(t(), t()) :: :lt | :eq | :gt
  def compare(%__MODULE__{timestamp: t1}, %__MODULE__{timestamp: t2}) do
    DateTime.compare(t1, t2)
  end

  @doc """
  Serializes an entry to a map for storage.
  """
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = entry) do
    %{
      "id" => entry.id,
      "timestamp" => DateTime.to_iso8601(entry.timestamp),
      "event_type" => Atom.to_string(entry.event_type),
      "actor_id" => entry.actor_id,
      "resource_id" => entry.resource_id,
      "details" => entry.details,
      "previous_hash" => encode_hash(entry.previous_hash),
      "entry_hash" => encode_hash(entry.entry_hash),
      "sequence_number" => entry.sequence_number
    }
  end

  @doc """
  Deserializes an entry from a map.
  """
  @spec from_map(map()) :: {:ok, t()} | {:error, term()}
  def from_map(map) when is_map(map) do
    with {:ok, timestamp} <- parse_timestamp(map["timestamp"]),
         {:ok, event_type} <- parse_event_type(map["event_type"]),
         {:ok, previous_hash} <- decode_hash(map["previous_hash"]),
         {:ok, entry_hash} <- decode_hash(map["entry_hash"]) do
      entry = %__MODULE__{
        id: map["id"],
        timestamp: timestamp,
        event_type: event_type,
        actor_id: map["actor_id"],
        resource_id: map["resource_id"],
        details: map["details"] || %{},
        previous_hash: previous_hash,
        entry_hash: entry_hash,
        sequence_number: map["sequence_number"]
      }

      {:ok, entry}
    end
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp generate_id do
    :crypto.strong_rand_bytes(16)
    |> Base.url_encode64(padding: false)
  end

  defp compute_hash(id, timestamp, event_type, actor_id, resource_id, details, previous_hash) do
    # Build deterministic input for hashing
    # Use length-prefixed encoding to prevent concatenation attacks
    input =
      [
        @domain_separator,
        encode_field(id),
        encode_field(DateTime.to_iso8601(timestamp)),
        encode_field(Atom.to_string(event_type)),
        encode_field(actor_id || ""),
        encode_field(resource_id || ""),
        encode_field(encode_details(details)),
        encode_field(previous_hash || <<>>)
      ]
      |> IO.iodata_to_binary()

    :crypto.hash(@hash_algorithm, input)
  end

  defp encode_field(value) when is_binary(value) do
    length = byte_size(value)
    <<length::32, value::binary>>
  end

  defp encode_details(details) when is_map(details) do
    # Sort keys for deterministic encoding
    details
    |> Enum.sort_by(fn {k, _v} -> to_string(k) end)
    |> Enum.map(fn {k, v} -> "#{k}=#{encode_value(v)}" end)
    |> Enum.join(";")
  end

  defp encode_value(value) when is_binary(value), do: value
  defp encode_value(value) when is_atom(value), do: Atom.to_string(value)
  defp encode_value(value) when is_number(value), do: to_string(value)
  defp encode_value(value) when is_list(value), do: Enum.map_join(value, ",", &encode_value/1)
  defp encode_value(value) when is_map(value), do: Jason.encode!(value)
  defp encode_value(nil), do: ""

  defp encode_hash(nil), do: nil
  defp encode_hash(hash) when is_binary(hash), do: Base.encode16(hash, case: :lower)

  defp decode_hash(nil), do: {:ok, nil}

  defp decode_hash(encoded) when is_binary(encoded) do
    case Base.decode16(encoded, case: :mixed) do
      {:ok, hash} -> {:ok, hash}
      :error -> {:error, :invalid_hash_encoding}
    end
  end

  defp parse_timestamp(nil), do: {:error, :missing_timestamp}

  defp parse_timestamp(timestamp) when is_binary(timestamp) do
    case DateTime.from_iso8601(timestamp) do
      {:ok, dt, _offset} -> {:ok, dt}
      {:error, _} -> {:error, :invalid_timestamp}
    end
  end

  defp parse_event_type(nil), do: {:error, :missing_event_type}

  defp parse_event_type(event_type) when is_binary(event_type) do
    {:ok, String.to_existing_atom(event_type)}
  rescue
    ArgumentError -> {:error, :unknown_event_type}
  end
end
