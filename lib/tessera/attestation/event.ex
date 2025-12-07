defmodule Tessera.Attestation.Event do
  @moduledoc """
  Represents an attestable event in the Tessera system.

  Events are the atomic units of attestation. Each event has a type,
  associated data, and can be individually attested or batched with
  other events for cost efficiency.

  ## Event Types

  - `:pod_creation` - A new pod was created
  - `:grant_issuance` - A temporal grant was issued
  - `:grant_revocation` - A grant was revoked
  - `:consensus_outcome` - Pod consensus was reached
  - `:key_rotation` - Epoch keys were rotated
  - `:epoch_boundary` - An epoch transition occurred
  """

  alias Tessera.Attestation

  @enforce_keys [:id, :type, :data, :hash, :created_at]
  defstruct [:id, :type, :data, :hash, :created_at, :attestation_id, :batch_id]

  @type t :: %__MODULE__{
          id: String.t(),
          type: Attestation.event_type(),
          data: map(),
          hash: binary(),
          created_at: DateTime.t(),
          attestation_id: Attestation.attestation_id() | nil,
          batch_id: Attestation.attestation_id() | nil
        }

  @doc """
  Creates a new event for attestation.

  ## Examples

      iex> {:ok, event} = Event.new(:pod_creation, %{pod_id: "pod_123"})
      iex> event.type
      :pod_creation
  """
  @spec new(Attestation.event_type(), map()) :: {:ok, t()} | {:error, :invalid_event_type}
  def new(type, data) when is_atom(type) and is_map(data) do
    if Attestation.valid_event_type?(type) do
      event = %__MODULE__{
        id: Attestation.generate_id(),
        type: type,
        data: data,
        hash: Attestation.hash_event(type, data),
        created_at: DateTime.utc_now(),
        attestation_id: nil,
        batch_id: nil
      }

      {:ok, event}
    else
      {:error, :invalid_event_type}
    end
  end

  @doc """
  Creates a pod creation event.
  """
  @spec pod_creation(String.t(), String.t(), keyword()) :: {:ok, t()} | {:error, term()}
  def pod_creation(pod_id, creator_id, opts \\ []) do
    data = %{
      pod_id: pod_id,
      creator_id: creator_id,
      metadata: Keyword.get(opts, :metadata, %{}),
      timestamp: DateTime.utc_now()
    }

    new(:pod_creation, data)
  end

  @doc """
  Creates a grant issuance event.
  """
  @spec grant_issuance(String.t(), String.t(), String.t(), keyword()) ::
          {:ok, t()} | {:error, term()}
  def grant_issuance(grant_id, grantor_id, grantee_id, opts \\ []) do
    data = %{
      grant_id: grant_id,
      grantor_id: grantor_id,
      grantee_id: grantee_id,
      resource_id: Keyword.get(opts, :resource_id),
      valid_from: Keyword.get(opts, :valid_from, DateTime.utc_now()),
      valid_until: Keyword.get(opts, :valid_until),
      permissions: Keyword.get(opts, :permissions, []),
      timestamp: DateTime.utc_now()
    }

    new(:grant_issuance, data)
  end

  @doc """
  Creates a grant revocation event.
  """
  @spec grant_revocation(String.t(), String.t(), keyword()) :: {:ok, t()} | {:error, term()}
  def grant_revocation(grant_id, revoker_id, opts \\ []) do
    data = %{
      grant_id: grant_id,
      revoker_id: revoker_id,
      reason: Keyword.get(opts, :reason),
      timestamp: DateTime.utc_now()
    }

    new(:grant_revocation, data)
  end

  @doc """
  Creates a consensus outcome event.
  """
  @spec consensus_outcome(String.t(), map(), keyword()) :: {:ok, t()} | {:error, term()}
  def consensus_outcome(pod_id, outcome, opts \\ []) do
    data = %{
      pod_id: pod_id,
      outcome: outcome,
      participants: Keyword.get(opts, :participants, []),
      round: Keyword.get(opts, :round, 1),
      timestamp: DateTime.utc_now()
    }

    new(:consensus_outcome, data)
  end

  @doc """
  Creates a key rotation event.
  """
  @spec key_rotation(String.t(), non_neg_integer(), keyword()) :: {:ok, t()} | {:error, term()}
  def key_rotation(pod_id, epoch_number, opts \\ []) do
    data = %{
      pod_id: pod_id,
      epoch_number: epoch_number,
      key_commitment: Keyword.get(opts, :key_commitment),
      previous_epoch: epoch_number - 1,
      timestamp: DateTime.utc_now()
    }

    new(:key_rotation, data)
  end

  @doc """
  Creates an epoch boundary event.
  """
  @spec epoch_boundary(non_neg_integer(), DateTime.t(), keyword()) ::
          {:ok, t()} | {:error, term()}
  def epoch_boundary(epoch_number, boundary_time, opts \\ []) do
    data = %{
      epoch_number: epoch_number,
      boundary_time: boundary_time,
      previous_epoch_hash: Keyword.get(opts, :previous_epoch_hash),
      pod_count: Keyword.get(opts, :pod_count, 0),
      timestamp: DateTime.utc_now()
    }

    new(:epoch_boundary, data)
  end

  @doc """
  Serializes an event to binary format.
  """
  @spec serialize(t()) :: {:ok, binary()} | {:error, term()}
  def serialize(%__MODULE__{} = event) do
    data = %{
      id: event.id,
      type: Atom.to_string(event.type),
      data: event.data,
      hash: Base.encode16(event.hash, case: :lower),
      created_at: DateTime.to_iso8601(event.created_at),
      attestation_id: event.attestation_id,
      batch_id: event.batch_id
    }

    {:ok, Jason.encode!(data)}
  rescue
    e -> {:error, {:serialization_failed, e}}
  end

  @doc """
  Deserializes an event from binary format.
  """
  @spec deserialize(binary()) :: {:ok, t()} | {:error, term()}
  def deserialize(binary) when is_binary(binary) do
    with {:ok, data} <- Jason.decode(binary),
         {:ok, hash} <- Base.decode16(data["hash"], case: :lower),
         {:ok, created_at, _} <- DateTime.from_iso8601(data["created_at"]) do
      event = %__MODULE__{
        id: data["id"],
        type: String.to_existing_atom(data["type"]),
        data: atomize_keys(data["data"]),
        hash: hash,
        created_at: created_at,
        attestation_id: data["attestation_id"],
        batch_id: data["batch_id"]
      }

      {:ok, event}
    end
  rescue
    e -> {:error, {:deserialization_failed, e}}
  end

  # Private helpers

  defp atomize_keys(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_binary(k) -> {String.to_atom(k), atomize_keys(v)}
      {k, v} -> {k, atomize_keys(v)}
    end)
  end

  defp atomize_keys(list) when is_list(list) do
    Enum.map(list, &atomize_keys/1)
  end

  defp atomize_keys(value), do: value
end
