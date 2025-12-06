defmodule Tessera.Crypto.ZK.Commitment do
  @moduledoc """
  Pedersen-style commitments using SHA-256.

  A commitment binds a prover to a value without revealing it. Later,
  the prover can open the commitment to prove they knew the value.

  ## Properties

  - **Hiding**: The commitment reveals nothing about the committed value
  - **Binding**: Cannot open the commitment to a different value

  ## Structure

  Commitments contain:
  - `value_hash` - Hash of the committed data
  - `public_data` - Public inputs visible to verifiers
  - `commitment_hash` - The actual commitment (hides the data)
  """

  @enforce_keys [:commitment_hash, :value_hash, :public_data, :type, :created_at]
  defstruct [:commitment_hash, :value_hash, :public_data, :type, :created_at]

  @type t :: %__MODULE__{
          commitment_hash: binary(),
          value_hash: binary(),
          public_data: map(),
          type: :participation | :value | :membership,
          created_at: DateTime.t()
        }

  @blinding_factor_size 32
  @hash_algorithm :sha256

  @doc """
  Creates a participation commitment.

  Commits to participation in a pod at a specific time without revealing
  the actual contribution.
  """
  @spec create_participation(String.t(), DateTime.t(), binary()) ::
          {:ok, t(), binary()} | {:error, term()}
  def create_participation(pod_id, timestamp, contribution)
      when is_binary(pod_id) and is_binary(contribution) do
    blinding_factor = :crypto.strong_rand_bytes(@blinding_factor_size)

    # Hash the contribution (value we're hiding)
    value_hash = hash(contribution)

    # Public data that will be visible
    public_data = %{
      pod_id: pod_id,
      timestamp: DateTime.to_iso8601(timestamp),
      timestamp_unix: DateTime.to_unix(timestamp)
    }

    # Create the commitment: H(pod_id || timestamp || value_hash || blinding_factor)
    commitment_input =
      pod_id <>
        Integer.to_string(DateTime.to_unix(timestamp)) <>
        value_hash <>
        blinding_factor

    commitment_hash = hash(commitment_input)

    # The secret includes both the contribution and blinding factor
    secret = encode_secret(contribution, blinding_factor)

    commitment = %__MODULE__{
      commitment_hash: commitment_hash,
      value_hash: value_hash,
      public_data: public_data,
      type: :participation,
      created_at: DateTime.utc_now()
    }

    {:ok, commitment, secret}
  end

  @doc """
  Creates a value commitment for range proofs.

  Commits to an integer value that can later be proven to be within a range.
  """
  @spec create_value(integer(), keyword()) :: {:ok, t(), binary()} | {:error, term()}
  def create_value(value, opts \\ []) when is_integer(value) do
    blinding_factor = :crypto.strong_rand_bytes(@blinding_factor_size)

    # Encode value as binary
    value_binary = :binary.encode_unsigned(value)
    value_hash = hash(value_binary)

    # Public data includes optional range hints
    public_data = %{
      min: Keyword.get(opts, :min),
      max: Keyword.get(opts, :max)
    }

    # Commitment: H(value || blinding_factor)
    commitment_input = value_binary <> blinding_factor
    commitment_hash = hash(commitment_input)

    secret = encode_secret(value_binary, blinding_factor)

    commitment = %__MODULE__{
      commitment_hash: commitment_hash,
      value_hash: value_hash,
      public_data: public_data,
      type: :value,
      created_at: DateTime.utc_now()
    }

    {:ok, commitment, secret}
  end

  @doc """
  Creates a membership commitment.

  Commits to being a member of a set without revealing which member.
  """
  @spec create_membership(term(), [term()]) :: {:ok, t(), binary()} | {:error, term()}
  def create_membership(element, set) when is_list(set) do
    if element not in set do
      {:error, :element_not_in_set}
    else
      blinding_factor = :crypto.strong_rand_bytes(@blinding_factor_size)

      # Serialize element
      element_binary = :erlang.term_to_binary(element)
      value_hash = hash(element_binary)

      # Compute merkle root of set for public verification
      set_root = compute_set_root(set)

      public_data = %{
        set_root: Base.encode16(set_root, case: :lower),
        set_size: length(set)
      }

      # Commitment: H(element || set_root || blinding_factor)
      commitment_input = element_binary <> set_root <> blinding_factor
      commitment_hash = hash(commitment_input)

      secret = encode_secret(element_binary, blinding_factor)

      commitment = %__MODULE__{
        commitment_hash: commitment_hash,
        value_hash: value_hash,
        public_data: public_data,
        type: :membership,
        created_at: DateTime.utc_now()
      }

      {:ok, commitment, secret}
    end
  end

  @doc """
  Verifies that a secret opens a commitment correctly.

  This is used internally during proof verification.
  """
  @spec verify_opening(t(), binary()) :: :ok | {:error, :invalid_opening}
  def verify_opening(%__MODULE__{} = commitment, secret) do
    case decode_secret(secret) do
      {:ok, value_binary, blinding_factor} ->
        # Recompute the commitment
        recomputed = recompute_commitment(commitment, value_binary, blinding_factor)

        if secure_compare(recomputed, commitment.commitment_hash) do
          :ok
        else
          {:error, :invalid_opening}
        end

      {:error, _} ->
        {:error, :invalid_opening}
    end
  end

  @doc """
  Extracts the value from a secret.
  """
  @spec extract_value(binary()) :: {:ok, binary()} | {:error, term()}
  def extract_value(secret) do
    case decode_secret(secret) do
      {:ok, value_binary, _blinding_factor} -> {:ok, value_binary}
      error -> error
    end
  end

  @doc """
  Extracts the blinding factor from a secret.
  """
  @spec extract_blinding_factor(binary()) :: {:ok, binary()} | {:error, term()}
  def extract_blinding_factor(secret) do
    case decode_secret(secret) do
      {:ok, _value_binary, blinding_factor} -> {:ok, blinding_factor}
      error -> error
    end
  end

  @doc """
  Serializes a commitment to binary.
  """
  @spec serialize(t()) :: {:ok, binary()} | {:error, term()}
  def serialize(%__MODULE__{} = commitment) do
    data = %{
      commitment_hash: Base.encode16(commitment.commitment_hash, case: :lower),
      value_hash: Base.encode16(commitment.value_hash, case: :lower),
      public_data: commitment.public_data,
      type: commitment.type,
      created_at: DateTime.to_iso8601(commitment.created_at)
    }

    {:ok, Jason.encode!(data)}
  rescue
    e -> {:error, {:serialization_failed, e}}
  end

  @doc """
  Deserializes a commitment from binary.
  """
  @spec deserialize(binary()) :: {:ok, t()} | {:error, term()}
  def deserialize(binary) when is_binary(binary) do
    with {:ok, data} <- Jason.decode(binary),
         {:ok, commitment_hash} <- Base.decode16(data["commitment_hash"], case: :lower),
         {:ok, value_hash} <- Base.decode16(data["value_hash"], case: :lower),
         {:ok, created_at, _} <- DateTime.from_iso8601(data["created_at"]) do
      commitment = %__MODULE__{
        commitment_hash: commitment_hash,
        value_hash: value_hash,
        public_data: atomize_keys(data["public_data"]),
        type: String.to_existing_atom(data["type"]),
        created_at: created_at
      }

      {:ok, commitment}
    end
  rescue
    e -> {:error, {:deserialization_failed, e}}
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp hash(data), do: :crypto.hash(@hash_algorithm, data)

  defp encode_secret(value_binary, blinding_factor) do
    value_size = byte_size(value_binary)
    <<value_size::32, value_binary::binary, blinding_factor::binary>>
  end

  defp decode_secret(<<value_size::32, rest::binary>>) do
    case rest do
      <<value_binary::binary-size(value_size),
        blinding_factor::binary-size(@blinding_factor_size)>> ->
        {:ok, value_binary, blinding_factor}

      _ ->
        {:error, :invalid_secret_format}
    end
  end

  defp decode_secret(_), do: {:error, :invalid_secret_format}

  defp recompute_commitment(
         %{type: :participation, public_data: pd},
         value_binary,
         blinding_factor
       ) do
    value_hash = hash(value_binary)

    commitment_input =
      pd.pod_id <>
        Integer.to_string(pd.timestamp_unix) <>
        value_hash <>
        blinding_factor

    hash(commitment_input)
  end

  defp recompute_commitment(%{type: :value}, value_binary, blinding_factor) do
    commitment_input = value_binary <> blinding_factor
    hash(commitment_input)
  end

  defp recompute_commitment(
         %{type: :membership, public_data: pd},
         element_binary,
         blinding_factor
       ) do
    {:ok, set_root} = Base.decode16(pd.set_root, case: :lower)
    commitment_input = element_binary <> set_root <> blinding_factor
    hash(commitment_input)
  end

  defp compute_set_root(set) do
    # Simple merkle root: hash all elements and combine
    leaves = Enum.map(set, fn elem -> hash(:erlang.term_to_binary(elem)) end)
    merkle_root(leaves)
  end

  defp merkle_root([single]), do: single

  defp merkle_root(leaves) do
    # Pad to even number
    padded =
      if rem(length(leaves), 2) == 1 do
        leaves ++ [List.last(leaves)]
      else
        leaves
      end

    # Combine pairs
    pairs =
      padded
      |> Enum.chunk_every(2)
      |> Enum.map(fn [left, right] -> hash(left <> right) end)

    merkle_root(pairs)
  end

  defp secure_compare(a, b) when byte_size(a) == byte_size(b) do
    :crypto.hash_equals(a, b)
  end

  defp secure_compare(_, _), do: false

  defp atomize_keys(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_binary(k) -> {String.to_existing_atom(k), v}
      {k, v} -> {k, v}
    end)
  rescue
    ArgumentError -> map
  end
end
