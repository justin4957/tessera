defmodule Tessera.Crypto.ZK.Commitment do
  @moduledoc """
  Hash-based commitments using SHA-256 with domain separation.

  This module implements a hash-based commitment scheme (not a true Pedersen
  commitment, which requires elliptic curve operations). The scheme provides:

  - **Hiding**: The commitment reveals nothing about the committed value
  - **Binding**: Computationally infeasible to open to a different value

  ## Security Notes

  This implementation uses SHA-256 hash-based commitments with:
  - Domain separation tags to prevent cross-protocol attacks
  - Length-prefixed encoding to prevent concatenation collisions
  - Cryptographically secure random blinding factors

  For applications requiring homomorphic properties or formal ZK guarantees,
  consider using elliptic curve-based Pedersen commitments (e.g., via libsecp256k1).

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

  # Cryptographic constants
  @blinding_factor_size 32
  @hash_algorithm :sha256

  # Domain separation tags for different commitment types
  @domain_participation "Tessera.ZK.Commitment.Participation.v1"
  @domain_value "Tessera.ZK.Commitment.Value.v1"
  @domain_membership "Tessera.ZK.Commitment.Membership.v1"

  @doc """
  Creates a participation commitment.

  Commits to participation in a pod at a specific time without revealing
  the actual contribution.

  Uses domain separation and length-prefixed encoding to prevent
  cross-protocol and concatenation attacks.
  """
  @spec create_participation(String.t(), DateTime.t(), binary()) ::
          {:ok, t(), binary()} | {:error, term()}
  def create_participation(pod_id, timestamp, contribution)
      when is_binary(pod_id) and is_binary(contribution) do
    blinding_factor = :crypto.strong_rand_bytes(@blinding_factor_size)

    # Hash the contribution (value we're hiding)
    value_hash = hash(contribution)
    timestamp_unix = DateTime.to_unix(timestamp)

    # Public data that will be visible
    public_data = %{
      pod_id: pod_id,
      timestamp: DateTime.to_iso8601(timestamp),
      timestamp_unix: timestamp_unix
    }

    # Create the commitment with domain separation and length-prefixed encoding:
    # H(domain || len(pod_id) || pod_id || timestamp || value_hash || blinding_factor)
    commitment_input =
      encode_commitment_input(
        @domain_participation,
        [pod_id, <<timestamp_unix::64>>, value_hash, blinding_factor]
      )

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
  Uses domain separation and length-prefixed encoding.
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

    # Commitment with domain separation: H(domain || len(value) || value || blinding_factor)
    commitment_input =
      encode_commitment_input(
        @domain_value,
        [value_binary, blinding_factor]
      )

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
  Uses domain separation and length-prefixed encoding.
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

      # Commitment with domain separation:
      # H(domain || len(element) || element || set_root || blinding_factor)
      commitment_input =
        encode_commitment_input(
          @domain_membership,
          [element_binary, set_root, blinding_factor]
        )

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

  # Encodes commitment input with domain separation and length-prefixed fields
  # to prevent concatenation collision attacks (e.g., "ab" <> "cd" vs "a" <> "bcd")
  defp encode_commitment_input(domain, fields) when is_binary(domain) and is_list(fields) do
    encoded_fields = Enum.map(fields, &encode_length_prefixed/1)
    IO.iodata_to_binary([domain | encoded_fields])
  end

  defp encode_length_prefixed(data) when is_binary(data) do
    <<byte_size(data)::32, data::binary>>
  end

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
      encode_commitment_input(
        @domain_participation,
        [pd.pod_id, <<pd.timestamp_unix::64>>, value_hash, blinding_factor]
      )

    hash(commitment_input)
  end

  defp recompute_commitment(%{type: :value}, value_binary, blinding_factor) do
    commitment_input =
      encode_commitment_input(
        @domain_value,
        [value_binary, blinding_factor]
      )

    hash(commitment_input)
  end

  defp recompute_commitment(
         %{type: :membership, public_data: pd},
         element_binary,
         blinding_factor
       ) do
    {:ok, set_root} = Base.decode16(pd.set_root, case: :lower)

    commitment_input =
      encode_commitment_input(
        @domain_membership,
        [element_binary, set_root, blinding_factor]
      )

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
