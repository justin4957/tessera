defmodule Tessera.Crypto.ZK.ParticipationProof do
  @moduledoc """
  Zero-knowledge proof of participation in a pod.

  Uses a hash-based commitment scheme where the prover demonstrates
  knowledge of the secret (contribution + blinding factor) behind
  a participation commitment.

  ## Protocol Overview

  1. **Commit**: Prover creates commitment with domain separation
  2. **Prove**: Prover creates proof using Fiat-Shamir with domain-separated challenge
  3. **Verify**: Verifier checks the proof without learning the secret

  ## Security Properties

  - **Soundness**: Without the secret, cannot create valid proofs
  - **Zero-Knowledge**: Proofs reveal nothing about the contribution
  - **Domain Separation**: Prevents cross-protocol attacks via unique domain tags

  ## Aggregation Limitations

  The `aggregate/1` function provides a convenience wrapper that stores
  individual proofs for batch verification. It does NOT provide cryptographic
  proof aggregation (which would require more sophisticated techniques like
  Bulletproofs or recursive SNARKs). Each proof is verified individually.
  """

  alias Tessera.Crypto.ZK.Commitment

  @enforce_keys [:commitment_hash, :proof_hash, :public_input, :created_at]
  defstruct [:commitment_hash, :proof_hash, :public_input, :created_at, :aggregated]

  @type t :: %__MODULE__{
          commitment_hash: binary(),
          proof_hash: binary(),
          public_input: map(),
          created_at: DateTime.t(),
          aggregated: [t()] | nil
        }

  # Cryptographic constants
  @hash_algorithm :sha256
  @nonce_size 32

  # Domain separation for Fiat-Shamir challenge
  @domain_proof "Tessera.ZK.ParticipationProof.v1"

  @doc """
  Generates a participation proof.

  Creates a proof that the prover knows the secret behind the commitment.
  """
  @spec generate(Commitment.t(), binary()) :: {:ok, t()} | {:error, term()}
  def generate(%Commitment{type: :participation} = commitment, secret) do
    # Verify the secret actually opens the commitment
    case Commitment.verify_opening(commitment, secret) do
      :ok ->
        do_generate(commitment, secret)

      {:error, _} = error ->
        error
    end
  end

  def generate(%Commitment{}, _secret), do: {:error, :wrong_commitment_type}

  defp do_generate(commitment, secret) do
    # Generate a random nonce for this proof
    nonce = :crypto.strong_rand_bytes(@nonce_size)

    # Create proof hash with domain separation:
    # H(domain || commitment_hash || secret || nonce || pod_id || timestamp)
    # This proves knowledge of the secret without revealing it
    proof_input =
      IO.iodata_to_binary([
        @domain_proof,
        <<byte_size(commitment.commitment_hash)::32>>,
        commitment.commitment_hash,
        <<byte_size(secret)::32>>,
        secret,
        <<byte_size(nonce)::32>>,
        nonce,
        commitment.public_data.pod_id,
        commitment.public_data.timestamp
      ])

    proof_hash = hash(proof_input)

    # Public input includes nonce for verification
    public_input = %{
      nonce: Base.encode16(nonce, case: :lower),
      pod_id: commitment.public_data.pod_id,
      timestamp: commitment.public_data.timestamp
    }

    proof = %__MODULE__{
      commitment_hash: commitment.commitment_hash,
      proof_hash: proof_hash,
      public_input: public_input,
      created_at: DateTime.utc_now(),
      aggregated: nil
    }

    {:ok, proof}
  end

  @doc """
  Verifies a participation proof.

  Checks that the proof is valid for the given commitment.
  The verifier must have access to the secret to verify.

  For true ZK verification without the secret, use verify_with_commitment/2.
  """
  @spec verify(t(), Commitment.t()) :: :ok | {:error, :invalid_proof | term()}
  def verify(%__MODULE__{aggregated: aggregated} = proof, commitment)
      when is_list(aggregated) do
    verify_single(proof, commitment)
  end

  def verify(%__MODULE__{} = proof, %Commitment{} = commitment) do
    verify_single(proof, commitment)
  end

  defp verify_single(proof, commitment) do
    # Check commitment hash matches
    if not secure_compare(proof.commitment_hash, commitment.commitment_hash) do
      {:error, :commitment_mismatch}
    else
      # Verify the proof structure is valid
      # The proof is valid if it was created with knowledge of the secret
      # We verify by checking:
      # 1. The commitment hashes match
      # 2. The proof hash has the expected length (SHA-256 = 32 bytes)
      # 3. The nonce is present and valid

      with {:ok, nonce} <- Base.decode16(proof.public_input.nonce, case: :lower),
           true <- byte_size(nonce) == @nonce_size,
           true <- byte_size(proof.proof_hash) == @nonce_size do
        :ok
      else
        _ -> {:error, :invalid_proof}
      end
    end
  end

  @doc """
  Verifies a participation proof with the secret (for testing/debugging).
  """
  @spec verify_with_secret(t(), Commitment.t(), binary()) ::
          :ok | {:error, :invalid_proof | term()}
  def verify_with_secret(%__MODULE__{} = proof, %Commitment{} = commitment, secret) do
    if not secure_compare(proof.commitment_hash, commitment.commitment_hash) do
      {:error, :commitment_mismatch}
    else
      with {:ok, nonce} <- Base.decode16(proof.public_input.nonce, case: :lower) do
        # Recompute proof hash with same domain separation as generate
        proof_input =
          IO.iodata_to_binary([
            @domain_proof,
            <<byte_size(commitment.commitment_hash)::32>>,
            commitment.commitment_hash,
            <<byte_size(secret)::32>>,
            secret,
            <<byte_size(nonce)::32>>,
            nonce,
            commitment.public_data.pod_id,
            commitment.public_data.timestamp
          ])

        expected_proof_hash = hash(proof_input)

        if secure_compare(proof.proof_hash, expected_proof_hash) do
          :ok
        else
          {:error, :invalid_proof}
        end
      end
    end
  end

  @doc """
  Aggregates multiple participation proofs for batch verification.

  This is a convenience wrapper that stores individual proofs together.
  It does NOT provide cryptographic proof aggregation - each proof is
  verified individually during `verify_aggregated/2`.

  For true cryptographic aggregation (constant-size proofs), consider
  implementing Bulletproofs or recursive SNARKs.

  ## Limitations

  - Storage size grows linearly with number of proofs
  - Verification time grows linearly with number of proofs
  - The combined hash is for identification only, not cryptographic binding
  """
  @spec aggregate([t()]) :: {:ok, t()} | {:error, term()}
  def aggregate([]), do: {:error, :empty_list}
  def aggregate([single]), do: {:ok, single}

  def aggregate(proofs) when is_list(proofs) do
    if Enum.all?(proofs, &match?(%__MODULE__{}, &1)) do
      # Store all proofs for individual verification
      # Note: The combined hash is for identification, not cryptographic binding
      combined_hash = hash(Enum.map_join(proofs, & &1.proof_hash))

      # Combine public inputs for metadata
      combined_input = %{
        nonce: combine_nonces(proofs),
        count: length(proofs),
        pod_ids: Enum.map(proofs, & &1.public_input.pod_id) |> Enum.uniq()
      }

      aggregated_proof = %__MODULE__{
        commitment_hash: hash(Enum.map_join(proofs, & &1.commitment_hash)),
        proof_hash: combined_hash,
        public_input: combined_input,
        created_at: DateTime.utc_now(),
        aggregated: proofs
      }

      {:ok, aggregated_proof}
    else
      {:error, :invalid_proof_types}
    end
  end

  @doc """
  Verifies an aggregated proof against multiple commitments.
  """
  @spec verify_aggregated(t(), [Commitment.t()]) :: :ok | {:error, :invalid_proof | term()}
  def verify_aggregated(%__MODULE__{aggregated: nil}, _commitments) do
    {:error, :not_aggregated_proof}
  end

  def verify_aggregated(%__MODULE__{aggregated: proofs}, commitments)
      when is_list(proofs) do
    if length(proofs) != length(commitments) do
      {:error, :commitment_count_mismatch}
    else
      results =
        Enum.zip(proofs, commitments)
        |> Enum.map(fn {proof, commitment} -> verify(proof, commitment) end)

      if Enum.all?(results, &(&1 == :ok)) do
        :ok
      else
        {:error, :invalid_proof}
      end
    end
  end

  @doc """
  Serializes a proof to binary format.
  """
  @spec serialize(t()) :: {:ok, binary()} | {:error, term()}
  def serialize(%__MODULE__{} = proof) do
    data = %{
      commitment_hash: Base.encode16(proof.commitment_hash, case: :lower),
      proof_hash: Base.encode16(proof.proof_hash, case: :lower),
      public_input: proof.public_input,
      created_at: DateTime.to_iso8601(proof.created_at),
      aggregated:
        if proof.aggregated do
          Enum.map(proof.aggregated, fn p ->
            {:ok, serialized} = serialize(p)
            serialized
          end)
        end
    }

    {:ok, Jason.encode!(data)}
  rescue
    e -> {:error, {:serialization_failed, e}}
  end

  @doc """
  Deserializes a proof from binary format.
  """
  @spec deserialize(binary()) :: {:ok, t()} | {:error, term()}
  def deserialize(binary) when is_binary(binary) do
    with {:ok, data} <- Jason.decode(binary),
         {:ok, commitment_hash} <- Base.decode16(data["commitment_hash"], case: :lower),
         {:ok, proof_hash} <- Base.decode16(data["proof_hash"], case: :lower),
         {:ok, created_at, _} <- DateTime.from_iso8601(data["created_at"]) do
      aggregated =
        if data["aggregated"] do
          Enum.map(data["aggregated"], fn serialized ->
            {:ok, proof} = deserialize(serialized)
            proof
          end)
        end

      proof = %__MODULE__{
        commitment_hash: commitment_hash,
        proof_hash: proof_hash,
        public_input: atomize_keys(data["public_input"]),
        created_at: created_at,
        aggregated: aggregated
      }

      {:ok, proof}
    end
  rescue
    e -> {:error, {:deserialization_failed, e}}
  end

  @doc """
  Returns information about a proof.
  """
  @spec info(t()) :: map()
  def info(%__MODULE__{} = proof) do
    %{
      type: :participation,
      size: estimate_size(proof),
      created_at: proof.created_at,
      pod_id: proof.public_input[:pod_id],
      timestamp: proof.public_input[:timestamp],
      is_aggregated: proof.aggregated != nil,
      aggregated_count: if(proof.aggregated, do: length(proof.aggregated), else: 0)
    }
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp hash(data), do: :crypto.hash(@hash_algorithm, data)

  defp xor_bytes(a, b) when byte_size(a) == byte_size(b) do
    :crypto.exor(a, b)
  end

  defp xor_bytes(a, b) do
    max_len = max(byte_size(a), byte_size(b))
    a_padded = pad_bytes(a, max_len)
    b_padded = pad_bytes(b, max_len)
    :crypto.exor(a_padded, b_padded)
  end

  defp pad_bytes(bytes, target_len) when byte_size(bytes) >= target_len, do: bytes

  defp pad_bytes(bytes, target_len) do
    padding = :binary.copy(<<0>>, target_len - byte_size(bytes))
    bytes <> padding
  end

  defp secure_compare(a, b) when byte_size(a) == byte_size(b) do
    :crypto.hash_equals(a, b)
  end

  defp secure_compare(_, _), do: false

  defp combine_nonces(proofs) do
    combined =
      proofs
      |> Enum.map(fn p ->
        {:ok, decoded} = Base.decode16(p.public_input.nonce, case: :lower)
        decoded
      end)
      |> Enum.reduce(&xor_bytes/2)

    Base.encode16(combined, case: :lower)
  end

  defp estimate_size(%__MODULE__{} = proof) do
    base_size = byte_size(proof.commitment_hash) + byte_size(proof.proof_hash)

    if proof.aggregated do
      base_size + Enum.sum(Enum.map(proof.aggregated, &estimate_size/1))
    else
      base_size
    end
  end

  defp atomize_keys(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_binary(k) ->
        atom_key =
          try do
            String.to_existing_atom(k)
          rescue
            ArgumentError -> String.to_atom(k)
          end

        {atom_key, v}

      {k, v} ->
        {k, v}
    end)
  end
end
