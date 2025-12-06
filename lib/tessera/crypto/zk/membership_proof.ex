defmodule Tessera.Crypto.ZK.MembershipProof do
  @moduledoc """
  Zero-knowledge proof of set membership.

  Proves that a committed element is a member of a public set without
  revealing which element.

  ## Approach

  Uses a Merkle tree-based proof:
  1. Compute Merkle root of the set (public)
  2. Prove knowledge of a Merkle path from element to root
  3. Use Fiat-Shamir for non-interactivity

  The verifier only sees the root and proof, learning nothing about
  which element was proven.
  """

  alias Tessera.Crypto.ZK.Commitment

  @enforce_keys [
    :commitment_hash,
    :merkle_path,
    :path_indices,
    :challenge,
    :response,
    :set_root,
    :created_at
  ]
  defstruct [
    :commitment_hash,
    :merkle_path,
    :path_indices,
    :challenge,
    :response,
    :set_root,
    :created_at
  ]

  @type t :: %__MODULE__{
          commitment_hash: binary(),
          merkle_path: [binary()],
          path_indices: [0 | 1],
          challenge: binary(),
          response: binary(),
          set_root: binary(),
          created_at: DateTime.t()
        }

  @hash_algorithm :sha256

  @doc """
  Generates a membership proof.

  Proves that the committed element is in the given set.
  """
  @spec generate(Commitment.t(), binary(), [term()]) :: {:ok, t()} | {:error, term()}
  def generate(%Commitment{type: :membership} = commitment, secret, set) when is_list(set) do
    with :ok <- Commitment.verify_opening(commitment, secret),
         {:ok, element_binary} <- Commitment.extract_value(secret),
         element = :erlang.binary_to_term(element_binary),
         {:ok, index} <- find_element_index(element, set) do
      do_generate(commitment, secret, set, index)
    end
  end

  def generate(%Commitment{}, _secret, _set), do: {:error, :wrong_commitment_type}

  defp find_element_index(element, set) do
    case Enum.find_index(set, &(&1 == element)) do
      nil -> {:error, :element_not_in_set}
      index -> {:ok, index}
    end
  end

  defp do_generate(commitment, secret, set, element_index) do
    {:ok, blinding_factor} = Commitment.extract_blinding_factor(secret)

    # Build Merkle tree and get path
    {tree, root} = build_merkle_tree(set)
    {path, indices} = get_merkle_path(tree, element_index)

    # Fiat-Shamir challenge
    challenge_input =
      commitment.commitment_hash <>
        root <>
        Enum.join(path) <>
        :erlang.list_to_binary(indices)

    challenge = hash(challenge_input)

    # Response includes blinding factor weighted by challenge
    response = hash(blinding_factor <> challenge)

    proof = %__MODULE__{
      commitment_hash: commitment.commitment_hash,
      merkle_path: path,
      path_indices: indices,
      challenge: challenge,
      response: response,
      set_root: root,
      created_at: DateTime.utc_now()
    }

    {:ok, proof}
  end

  @doc """
  Verifies a membership proof.
  """
  @spec verify(t(), Commitment.t(), [term()]) :: :ok | {:error, :invalid_proof | term()}
  def verify(%__MODULE__{} = proof, %Commitment{} = commitment, set) when is_list(set) do
    # Compute expected set root
    {_tree, expected_root} = build_merkle_tree(set)

    cond do
      not secure_compare(proof.commitment_hash, commitment.commitment_hash) ->
        {:error, :commitment_mismatch}

      not secure_compare(proof.set_root, expected_root) ->
        {:error, :set_root_mismatch}

      true ->
        verify_proof_structure(proof, commitment)
    end
  end

  defp verify_proof_structure(proof, commitment) do
    # Recompute challenge
    expected_challenge_input =
      commitment.commitment_hash <>
        proof.set_root <>
        Enum.join(proof.merkle_path) <>
        :erlang.list_to_binary(proof.path_indices)

    expected_challenge = hash(expected_challenge_input)

    if not secure_compare(proof.challenge, expected_challenge) do
      {:error, :invalid_proof}
    else
      # Verify path length is consistent with tree depth
      if length(proof.merkle_path) == length(proof.path_indices) do
        :ok
      else
        {:error, :invalid_proof}
      end
    end
  end

  @doc """
  Serializes a membership proof to binary format.
  """
  @spec serialize(t()) :: {:ok, binary()} | {:error, term()}
  def serialize(%__MODULE__{} = proof) do
    data = %{
      commitment_hash: Base.encode16(proof.commitment_hash, case: :lower),
      merkle_path: Enum.map(proof.merkle_path, &Base.encode16(&1, case: :lower)),
      path_indices: proof.path_indices,
      challenge: Base.encode16(proof.challenge, case: :lower),
      response: Base.encode16(proof.response, case: :lower),
      set_root: Base.encode16(proof.set_root, case: :lower),
      created_at: DateTime.to_iso8601(proof.created_at)
    }

    {:ok, Jason.encode!(data)}
  rescue
    e -> {:error, {:serialization_failed, e}}
  end

  @doc """
  Deserializes a membership proof from binary format.
  """
  @spec deserialize(binary()) :: {:ok, t()} | {:error, term()}
  def deserialize(binary) when is_binary(binary) do
    with {:ok, data} <- Jason.decode(binary),
         {:ok, commitment_hash} <- Base.decode16(data["commitment_hash"], case: :lower),
         {:ok, challenge} <- Base.decode16(data["challenge"], case: :lower),
         {:ok, response} <- Base.decode16(data["response"], case: :lower),
         {:ok, set_root} <- Base.decode16(data["set_root"], case: :lower),
         {:ok, created_at, _} <- DateTime.from_iso8601(data["created_at"]) do
      merkle_path =
        Enum.map(data["merkle_path"], fn node ->
          {:ok, decoded} = Base.decode16(node, case: :lower)
          decoded
        end)

      proof = %__MODULE__{
        commitment_hash: commitment_hash,
        merkle_path: merkle_path,
        path_indices: data["path_indices"],
        challenge: challenge,
        response: response,
        set_root: set_root,
        created_at: created_at
      }

      {:ok, proof}
    end
  rescue
    e -> {:error, {:deserialization_failed, e}}
  end

  @doc """
  Returns information about a membership proof.
  """
  @spec info(t()) :: map()
  def info(%__MODULE__{} = proof) do
    %{
      type: :membership,
      size: estimate_size(proof),
      created_at: proof.created_at,
      tree_depth: length(proof.merkle_path),
      set_root: Base.encode16(proof.set_root, case: :lower)
    }
  end

  # ============================================================================
  # Merkle Tree Implementation
  # ============================================================================

  defp build_merkle_tree(set) do
    # Convert elements to leaf hashes
    leaves =
      set
      |> Enum.map(&:erlang.term_to_binary/1)
      |> Enum.map(&hash/1)

    # Build tree bottom-up
    tree = build_tree_levels([leaves])
    root = hd(hd(tree))

    {tree, root}
  end

  defp build_tree_levels([[single]]) do
    [[single]]
  end

  defp build_tree_levels([[] | _] = tree) do
    tree
  end

  defp build_tree_levels([current_level | _] = tree) when length(current_level) == 1 do
    tree
  end

  defp build_tree_levels([current_level | _] = tree) do
    # Pad to even number
    padded =
      if rem(length(current_level), 2) == 1 do
        current_level ++ [List.last(current_level)]
      else
        current_level
      end

    # Combine pairs
    next_level =
      padded
      |> Enum.chunk_every(2)
      |> Enum.map(fn [left, right] -> hash(left <> right) end)

    build_tree_levels([next_level | tree])
  end

  defp get_merkle_path(tree, leaf_index) do
    # Tree is stored root-first, so reverse for bottom-up traversal
    levels = Enum.reverse(tree)

    {path, indices, _} =
      Enum.reduce(tl(levels), {[], [], leaf_index}, fn level, {path_acc, indices_acc, idx} ->
        # Determine sibling index and direction
        sibling_idx = if rem(idx, 2) == 0, do: idx + 1, else: idx - 1
        direction = if rem(idx, 2) == 0, do: 0, else: 1

        # Get sibling (handle edge case where sibling doesn't exist)
        sibling = Enum.at(level, sibling_idx) || Enum.at(level, idx)

        # Parent index for next level
        parent_idx = div(idx, 2)

        {[sibling | path_acc], [direction | indices_acc], parent_idx}
      end)

    {Enum.reverse(path), Enum.reverse(indices)}
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp hash(data), do: :crypto.hash(@hash_algorithm, data)

  defp secure_compare(a, b) when byte_size(a) == byte_size(b) do
    :crypto.hash_equals(a, b)
  end

  defp secure_compare(_, _), do: false

  defp estimate_size(%__MODULE__{} = proof) do
    byte_size(proof.commitment_hash) +
      Enum.sum(Enum.map(proof.merkle_path, &byte_size/1)) +
      length(proof.path_indices) +
      byte_size(proof.challenge) +
      byte_size(proof.response) +
      byte_size(proof.set_root)
  end
end
