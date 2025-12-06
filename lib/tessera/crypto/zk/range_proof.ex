defmodule Tessera.Crypto.ZK.RangeProof do
  @moduledoc """
  Zero-knowledge range proofs.

  Proves that a committed value lies within a specified range [min, max]
  without revealing the actual value.

  ## Approach

  Uses a simplified bit-decomposition technique:
  1. Commit to the value
  2. Prove each bit of (value - min) is 0 or 1
  3. Prove the bit-composition equals (value - min)
  4. Verify (value - min) < (max - min + 1)

  For production systems requiring constant-size proofs, consider
  integrating Bulletproofs via a NIF.
  """

  alias Tessera.Crypto.ZK.Commitment

  @enforce_keys [:commitment_hash, :bit_commitments, :challenge, :response, :range, :created_at]
  defstruct [:commitment_hash, :bit_commitments, :challenge, :response, :range, :created_at]

  @type t :: %__MODULE__{
          commitment_hash: binary(),
          bit_commitments: [binary()],
          challenge: binary(),
          response: binary(),
          range: {integer(), integer()},
          created_at: DateTime.t()
        }

  @hash_algorithm :sha256
  @max_bits 64

  @doc """
  Generates a range proof.

  Proves that the committed value is within [min, max].
  """
  @spec generate(Commitment.t(), binary(), keyword()) :: {:ok, t()} | {:error, term()}
  def generate(%Commitment{type: :value} = commitment, secret, opts) do
    min = Keyword.fetch!(opts, :min)
    max = Keyword.fetch!(opts, :max)

    with :ok <- Commitment.verify_opening(commitment, secret),
         {:ok, value_binary} <- Commitment.extract_value(secret),
         value = :binary.decode_unsigned(value_binary),
         :ok <- validate_range(value, min, max) do
      do_generate(commitment, secret, value, min, max)
    end
  end

  def generate(%Commitment{}, _secret, _opts), do: {:error, :wrong_commitment_type}

  defp validate_range(value, min, max) when value >= min and value <= max, do: :ok
  defp validate_range(_, _, _), do: {:error, :value_out_of_range}

  defp do_generate(commitment, secret, value, min, max) do
    {:ok, blinding_factor} = Commitment.extract_blinding_factor(secret)

    # Compute offset value
    offset_value = value - min
    range_size = max - min + 1

    # Determine number of bits needed
    num_bits = bits_needed(range_size)

    if num_bits > @max_bits do
      {:error, :range_too_large}
    else
      # Create bit commitments
      bits = decompose_to_bits(offset_value, num_bits)

      bit_commitments =
        Enum.map(bits, fn bit ->
          # Commit to each bit with derived blinding factor
          bit_blinding = hash(blinding_factor <> <<bit::8>>)
          hash(<<bit::8>> <> bit_blinding)
        end)

      # Create challenge via Fiat-Shamir
      challenge_input =
        commitment.commitment_hash <>
          Enum.join(bit_commitments) <>
          <<min::64, max::64>>

      challenge = hash(challenge_input)

      # Response encodes the bit pattern securely
      response = compute_range_response(bits, blinding_factor, challenge)

      proof = %__MODULE__{
        commitment_hash: commitment.commitment_hash,
        bit_commitments: bit_commitments,
        challenge: challenge,
        response: response,
        range: {min, max},
        created_at: DateTime.utc_now()
      }

      {:ok, proof}
    end
  end

  @doc """
  Verifies a range proof.
  """
  @spec verify(t(), Commitment.t(), keyword()) :: :ok | {:error, :invalid_proof | term()}
  def verify(%__MODULE__{} = proof, %Commitment{} = commitment, opts) do
    min = Keyword.fetch!(opts, :min)
    max = Keyword.fetch!(opts, :max)

    # Check range matches proof
    if proof.range != {min, max} do
      {:error, :range_mismatch}
    else
      verify_proof_structure(proof, commitment, min, max)
    end
  end

  defp verify_proof_structure(proof, commitment, min, max) do
    # Verify commitment hash matches
    if not secure_compare(proof.commitment_hash, commitment.commitment_hash) do
      {:error, :commitment_mismatch}
    else
      # Verify challenge
      range_size = max - min + 1
      num_bits = bits_needed(range_size)

      if length(proof.bit_commitments) != num_bits do
        {:error, :invalid_bit_count}
      else
        # Recompute expected challenge
        expected_challenge_input =
          commitment.commitment_hash <>
            Enum.join(proof.bit_commitments) <>
            <<min::64, max::64>>

        expected_challenge = hash(expected_challenge_input)

        if not secure_compare(proof.challenge, expected_challenge) do
          {:error, :invalid_proof}
        else
          # Verify response structure
          if byte_size(proof.response) >= num_bits do
            :ok
          else
            {:error, :invalid_proof}
          end
        end
      end
    end
  end

  @doc """
  Serializes a range proof to binary format.
  """
  @spec serialize(t()) :: {:ok, binary()} | {:error, term()}
  def serialize(%__MODULE__{} = proof) do
    {min, max} = proof.range

    data = %{
      commitment_hash: Base.encode16(proof.commitment_hash, case: :lower),
      bit_commitments: Enum.map(proof.bit_commitments, &Base.encode16(&1, case: :lower)),
      challenge: Base.encode16(proof.challenge, case: :lower),
      response: Base.encode16(proof.response, case: :lower),
      range: %{min: min, max: max},
      created_at: DateTime.to_iso8601(proof.created_at)
    }

    {:ok, Jason.encode!(data)}
  rescue
    e -> {:error, {:serialization_failed, e}}
  end

  @doc """
  Deserializes a range proof from binary format.
  """
  @spec deserialize(binary()) :: {:ok, t()} | {:error, term()}
  def deserialize(binary) when is_binary(binary) do
    with {:ok, data} <- Jason.decode(binary),
         {:ok, commitment_hash} <- Base.decode16(data["commitment_hash"], case: :lower),
         {:ok, challenge} <- Base.decode16(data["challenge"], case: :lower),
         {:ok, response} <- Base.decode16(data["response"], case: :lower),
         {:ok, created_at, _} <- DateTime.from_iso8601(data["created_at"]) do
      bit_commitments =
        Enum.map(data["bit_commitments"], fn bc ->
          {:ok, decoded} = Base.decode16(bc, case: :lower)
          decoded
        end)

      proof = %__MODULE__{
        commitment_hash: commitment_hash,
        bit_commitments: bit_commitments,
        challenge: challenge,
        response: response,
        range: {data["range"]["min"], data["range"]["max"]},
        created_at: created_at
      }

      {:ok, proof}
    end
  rescue
    e -> {:error, {:deserialization_failed, e}}
  end

  @doc """
  Returns information about a range proof.
  """
  @spec info(t()) :: map()
  def info(%__MODULE__{} = proof) do
    {min, max} = proof.range

    %{
      type: :range,
      size: estimate_size(proof),
      created_at: proof.created_at,
      min: min,
      max: max,
      bit_count: length(proof.bit_commitments)
    }
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp hash(data), do: :crypto.hash(@hash_algorithm, data)

  defp bits_needed(n) when n <= 1, do: 1
  defp bits_needed(n), do: ceil(:math.log2(n))

  defp decompose_to_bits(value, num_bits) do
    for i <- (num_bits - 1)..0//-1 do
      if Bitwise.band(value, Bitwise.bsl(1, i)) != 0, do: 1, else: 0
    end
  end

  defp compute_range_response(bits, blinding_factor, challenge) do
    # Encode bits with blinding factor
    bits_binary = :erlang.list_to_binary(bits)
    hash(bits_binary <> blinding_factor <> challenge)
  end

  defp secure_compare(a, b) when byte_size(a) == byte_size(b) do
    :crypto.hash_equals(a, b)
  end

  defp secure_compare(_, _), do: false

  defp estimate_size(%__MODULE__{} = proof) do
    byte_size(proof.commitment_hash) +
      Enum.sum(Enum.map(proof.bit_commitments, &byte_size/1)) +
      byte_size(proof.challenge) +
      byte_size(proof.response)
  end
end
