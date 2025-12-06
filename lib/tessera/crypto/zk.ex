defmodule Tessera.Crypto.ZK do
  @moduledoc """
  Zero-Knowledge proof primitives for participation verification.

  This module implements ZK proofs for proving participation in Ephemeral
  Consensus Pods without revealing the actual data or contributions. It uses
  a commitment-based approach with hash proofs that provides:

  - **Soundness**: Proofs cannot be forged without the private witness
  - **Zero-Knowledge**: Proofs reveal nothing beyond the claimed statement
  - **Efficiency**: Proof generation and verification in milliseconds

  ## Proof Types

  ### Participation Proofs
  Prove "I participated in pod P at time T" without revealing what was contributed.

  ### Contribution Proofs
  Prove "My contribution satisfies constraint C" (e.g., matches a schema hash,
  falls within a range) without revealing the contribution itself.

  ### Membership Proofs
  Prove "I am a member of set S" without revealing which member.

  ## Cryptographic Approach

  This implementation uses a Pedersen-like commitment scheme with SHA-256:
  - Commitments: `C = H(data || blinding_factor)`
  - Proofs: Schnorr-like protocols using Fiat-Shamir heuristic

  For production use with stronger guarantees, consider integrating:
  - Bulletproofs (range proofs, no trusted setup)
  - Groth16/PLONK (general-purpose, requires trusted setup or universal SRS)

  ## Usage

      alias Tessera.Crypto.ZK

      # Create a participation commitment
      {:ok, commitment, secret} = ZK.commit_participation(
        "pod-123",
        ~U[2024-06-15 10:30:00Z],
        "my-contribution-data"
      )

      # Generate a proof
      {:ok, proof} = ZK.prove_participation(commitment, secret)

      # Verify the proof
      :ok = ZK.verify_participation(proof, commitment)

      # Aggregate multiple proofs
      {:ok, aggregated} = ZK.aggregate_proofs([proof1, proof2, proof3])
  """

  alias Tessera.Crypto.ZK.{Commitment, ParticipationProof, MembershipProof, RangeProof}

  @type proof :: ParticipationProof.t() | MembershipProof.t() | RangeProof.t()
  @type commitment :: Commitment.t()
  @type secret :: binary()
  @type public_input :: map()

  # ============================================================================
  # Commitment Operations
  # ============================================================================

  @doc """
  Creates a commitment to participation in a pod.

  The commitment hides the actual contribution while binding to the pod ID
  and timestamp. Returns the commitment and a secret needed for proving.

  ## Parameters

  - `pod_id` - Identifier of the pod
  - `timestamp` - When participation occurred
  - `contribution` - The actual contribution data (will be hidden)

  ## Returns

  - `{:ok, commitment, secret}` - Commitment and secret for later proving
  - `{:error, term}` - If commitment fails

  ## Examples

      {:ok, commitment, secret} = ZK.commit_participation(
        "pod-123",
        ~U[2024-06-15 10:30:00Z],
        "my vote: yes"
      )
  """
  @spec commit_participation(String.t(), DateTime.t(), binary()) ::
          {:ok, Commitment.t(), secret()} | {:error, term()}
  defdelegate commit_participation(pod_id, timestamp, contribution),
    to: Commitment,
    as: :create_participation

  @doc """
  Creates a commitment to a value for range proofs.

  ## Examples

      {:ok, commitment, secret} = ZK.commit_value(42, min: 0, max: 100)
  """
  @spec commit_value(integer(), keyword()) ::
          {:ok, Commitment.t(), secret()} | {:error, term()}
  defdelegate commit_value(value, opts \\ []), to: Commitment, as: :create_value

  @doc """
  Creates a commitment to set membership.

  ## Examples

      {:ok, commitment, secret} = ZK.commit_membership("alice", ["alice", "bob", "carol"])
  """
  @spec commit_membership(term(), [term()]) ::
          {:ok, Commitment.t(), secret()} | {:error, term()}
  defdelegate commit_membership(element, set), to: Commitment, as: :create_membership

  # ============================================================================
  # Proof Generation
  # ============================================================================

  @doc """
  Generates a ZK proof of participation.

  Creates a proof that the prover knows the secret behind a participation
  commitment, without revealing the contribution.

  ## Parameters

  - `commitment` - The participation commitment
  - `secret` - The secret from commitment creation

  ## Returns

  - `{:ok, proof}` - Valid participation proof
  - `{:error, term}` - If proof generation fails

  ## Examples

      {:ok, proof} = ZK.prove_participation(commitment, secret)
  """
  @spec prove_participation(Commitment.t(), secret()) ::
          {:ok, ParticipationProof.t()} | {:error, term()}
  defdelegate prove_participation(commitment, secret), to: ParticipationProof, as: :generate

  @doc """
  Generates a ZK proof that a committed value is within a range.

  ## Examples

      {:ok, proof} = ZK.prove_range(commitment, secret, min: 0, max: 100)
  """
  @spec prove_range(Commitment.t(), secret(), keyword()) ::
          {:ok, RangeProof.t()} | {:error, term()}
  defdelegate prove_range(commitment, secret, opts), to: RangeProof, as: :generate

  @doc """
  Generates a ZK proof of set membership.

  ## Examples

      {:ok, proof} = ZK.prove_membership(commitment, secret, set)
  """
  @spec prove_membership(Commitment.t(), secret(), [term()]) ::
          {:ok, MembershipProof.t()} | {:error, term()}
  defdelegate prove_membership(commitment, secret, set), to: MembershipProof, as: :generate

  # ============================================================================
  # Proof Verification
  # ============================================================================

  @doc """
  Verifies a participation proof.

  Checks that the proof is valid for the given commitment without
  learning anything about the underlying contribution.

  ## Parameters

  - `proof` - The participation proof
  - `commitment` - The commitment being proven

  ## Returns

  - `:ok` - Proof is valid
  - `{:error, :invalid_proof}` - Proof verification failed
  - `{:error, term}` - Other verification error

  ## Examples

      :ok = ZK.verify_participation(proof, commitment)
      {:error, :invalid_proof} = ZK.verify_participation(bad_proof, commitment)
  """
  @spec verify_participation(ParticipationProof.t(), Commitment.t()) ::
          :ok | {:error, :invalid_proof | term()}
  defdelegate verify_participation(proof, commitment), to: ParticipationProof, as: :verify

  @doc """
  Verifies a range proof.

  ## Examples

      :ok = ZK.verify_range(proof, commitment, min: 0, max: 100)
  """
  @spec verify_range(RangeProof.t(), Commitment.t(), keyword()) ::
          :ok | {:error, :invalid_proof | term()}
  defdelegate verify_range(proof, commitment, opts), to: RangeProof, as: :verify

  @doc """
  Verifies a membership proof.

  ## Examples

      :ok = ZK.verify_membership(proof, commitment, set)
  """
  @spec verify_membership(MembershipProof.t(), Commitment.t(), [term()]) ::
          :ok | {:error, :invalid_proof | term()}
  defdelegate verify_membership(proof, commitment, set), to: MembershipProof, as: :verify

  # ============================================================================
  # Proof Aggregation
  # ============================================================================

  @doc """
  Aggregates multiple participation proofs into a single proof.

  The aggregated proof proves that all individual proofs are valid,
  while being more compact than storing them separately.

  ## Parameters

  - `proofs` - List of participation proofs to aggregate

  ## Returns

  - `{:ok, aggregated_proof}` - Combined proof
  - `{:error, :empty_list}` - No proofs provided
  - `{:error, term}` - Aggregation failed

  ## Examples

      {:ok, aggregated} = ZK.aggregate_proofs([proof1, proof2, proof3])
  """
  @spec aggregate_proofs([ParticipationProof.t()]) ::
          {:ok, ParticipationProof.t()} | {:error, term()}
  defdelegate aggregate_proofs(proofs), to: ParticipationProof, as: :aggregate

  @doc """
  Verifies an aggregated proof against multiple commitments.

  ## Examples

      :ok = ZK.verify_aggregated(aggregated_proof, [commit1, commit2, commit3])
  """
  @spec verify_aggregated(ParticipationProof.t(), [Commitment.t()]) ::
          :ok | {:error, :invalid_proof | term()}
  defdelegate verify_aggregated(proof, commitments),
    to: ParticipationProof,
    as: :verify_aggregated

  # ============================================================================
  # Utility Functions
  # ============================================================================

  @doc """
  Serializes a proof to binary format for storage or transmission.

  ## Examples

      {:ok, bytes} = ZK.serialize_proof(proof)
  """
  @spec serialize_proof(proof()) :: {:ok, binary()} | {:error, term()}
  def serialize_proof(%ParticipationProof{} = proof), do: ParticipationProof.serialize(proof)
  def serialize_proof(%RangeProof{} = proof), do: RangeProof.serialize(proof)
  def serialize_proof(%MembershipProof{} = proof), do: MembershipProof.serialize(proof)
  def serialize_proof(_), do: {:error, :unknown_proof_type}

  @doc """
  Deserializes a proof from binary format.

  ## Examples

      {:ok, proof} = ZK.deserialize_proof(bytes, :participation)
  """
  @spec deserialize_proof(binary(), atom()) :: {:ok, proof()} | {:error, term()}
  def deserialize_proof(bytes, :participation), do: ParticipationProof.deserialize(bytes)
  def deserialize_proof(bytes, :range), do: RangeProof.deserialize(bytes)
  def deserialize_proof(bytes, :membership), do: MembershipProof.deserialize(bytes)
  def deserialize_proof(_, _), do: {:error, :unknown_proof_type}

  @doc """
  Returns information about a proof without verifying it.

  ## Examples

      info = ZK.proof_info(proof)
      # => %{type: :participation, size: 128, created_at: ~U[...]}
  """
  @spec proof_info(proof()) :: map()
  def proof_info(%ParticipationProof{} = proof), do: ParticipationProof.info(proof)
  def proof_info(%RangeProof{} = proof), do: RangeProof.info(proof)
  def proof_info(%MembershipProof{} = proof), do: MembershipProof.info(proof)
  def proof_info(_), do: %{type: :unknown}
end
