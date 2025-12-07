defmodule Tessera.Attestation.Batch do
  @moduledoc """
  Merkle tree-based batching for attestations.

  Batching multiple attestations into a single blockchain transaction
  reduces costs by approximately 10x compared to individual attestations.

  ## How It Works

  1. Events are collected into a batch
  2. Event hashes form the leaves of a Merkle tree
  3. The Merkle root is attested on-chain
  4. Individual events can be verified using Merkle proofs

  ## Verification

  To verify an event is part of a batch:
  1. Retrieve the batch's Merkle root from the blockchain
  2. Compute the event's hash
  3. Verify the Merkle proof connects the event hash to the root

  ## Example

      # Create a batch
      {:ok, batch} = Batch.new([event1, event2, event3])

      # Get proof for a specific event
      {:ok, proof} = Batch.get_proof(batch, event2.id)

      # Verify inclusion
      :ok = Batch.verify_inclusion(batch.merkle_root, event2.hash, proof)
  """

  alias Tessera.Attestation
  alias Tessera.Attestation.Event

  @enforce_keys [:id, :events, :merkle_root, :merkle_tree, :created_at]
  defstruct [
    :id,
    :events,
    :merkle_root,
    :merkle_tree,
    :created_at,
    :tx_hash,
    :block_number,
    :chain,
    :status
  ]

  @type merkle_proof :: [binary()]

  @type t :: %__MODULE__{
          id: Attestation.attestation_id(),
          events: [Event.t()],
          merkle_root: binary(),
          merkle_tree: [[binary()]],
          created_at: DateTime.t(),
          tx_hash: Attestation.tx_hash() | nil,
          block_number: Attestation.block_number() | nil,
          chain: Attestation.chain() | nil,
          status: :pending | :confirmed | :failed | nil
        }

  @hash_algorithm :sha256
  @max_batch_size 100

  @doc """
  Creates a new batch from a list of events.

  Builds a Merkle tree from the event hashes and computes the root.

  ## Options

  - `:max_size` - Maximum batch size (default: 100)

  ## Examples

      iex> {:ok, e1} = Event.new(:pod_creation, %{pod_id: "p1"})
      iex> {:ok, e2} = Event.new(:pod_creation, %{pod_id: "p2"})
      iex> {:ok, batch} = Batch.new([e1, e2])
      iex> length(batch.events)
      2
  """
  @spec new([Event.t()], keyword()) :: {:ok, t()} | {:error, term()}
  def new(events, opts \\ []) when is_list(events) do
    max_size = Keyword.get(opts, :max_size, @max_batch_size)

    cond do
      events == [] ->
        {:error, :empty_batch}

      length(events) > max_size ->
        {:error, {:batch_too_large, max_size}}

      true ->
        do_create_batch(events)
    end
  end

  defp do_create_batch(events) do
    # Extract hashes from events
    leaves = Enum.map(events, & &1.hash)

    # Build Merkle tree
    {tree, root} = build_merkle_tree(leaves)

    batch = %__MODULE__{
      id: Attestation.generate_id(),
      events: events,
      merkle_root: root,
      merkle_tree: tree,
      created_at: DateTime.utc_now(),
      tx_hash: nil,
      block_number: nil,
      chain: nil,
      status: :pending
    }

    {:ok, batch}
  end

  @doc """
  Gets the Merkle proof for an event in the batch.

  The proof is a list of sibling hashes needed to reconstruct
  the path from the event's leaf to the root.
  """
  @spec get_proof(t(), String.t()) :: {:ok, merkle_proof()} | {:error, :event_not_found}
  def get_proof(%__MODULE__{} = batch, event_id) do
    case Enum.find_index(batch.events, &(&1.id == event_id)) do
      nil ->
        {:error, :event_not_found}

      index ->
        proof = compute_merkle_proof(batch.merkle_tree, index)
        {:ok, proof}
    end
  end

  @doc """
  Gets the Merkle proof for an event by its hash.
  """
  @spec get_proof_by_hash(t(), binary()) :: {:ok, merkle_proof()} | {:error, :event_not_found}
  def get_proof_by_hash(%__MODULE__{} = batch, event_hash) do
    leaves = List.last(batch.merkle_tree)

    case Enum.find_index(leaves, &(&1 == event_hash)) do
      nil ->
        {:error, :event_not_found}

      index ->
        proof = compute_merkle_proof(batch.merkle_tree, index)
        {:ok, proof}
    end
  end

  @doc """
  Verifies that an event hash is included in a batch.

  Given the Merkle root, event hash, and proof, verifies that
  the event is part of the batch without needing the full batch data.
  """
  @spec verify_inclusion(binary(), binary(), merkle_proof()) :: :ok | {:error, :invalid_proof}
  def verify_inclusion(merkle_root, event_hash, proof) do
    computed_root = compute_root_from_proof(event_hash, proof)

    if secure_compare(computed_root, merkle_root) do
      :ok
    else
      {:error, :invalid_proof}
    end
  end

  @doc """
  Returns the event IDs in the batch.
  """
  @spec event_ids(t()) :: [String.t()]
  def event_ids(%__MODULE__{events: events}) do
    Enum.map(events, & &1.id)
  end

  @doc """
  Returns the number of events in the batch.
  """
  @spec size(t()) :: non_neg_integer()
  def size(%__MODULE__{events: events}), do: length(events)

  @doc """
  Finds an event in the batch by ID.
  """
  @spec find_event(t(), String.t()) :: {:ok, Event.t()} | {:error, :not_found}
  def find_event(%__MODULE__{events: events}, event_id) do
    case Enum.find(events, &(&1.id == event_id)) do
      nil -> {:error, :not_found}
      event -> {:ok, event}
    end
  end

  @doc """
  Updates the batch with blockchain confirmation details.
  """
  @spec confirm(t(), Attestation.tx_hash(), Attestation.block_number(), Attestation.chain()) ::
          t()
  def confirm(%__MODULE__{} = batch, tx_hash, block_number, chain) do
    %{batch | tx_hash: tx_hash, block_number: block_number, chain: chain, status: :confirmed}
  end

  @doc """
  Marks the batch as failed.
  """
  @spec fail(t(), term()) :: t()
  def fail(%__MODULE__{} = batch, _reason) do
    %{batch | status: :failed}
  end

  @doc """
  Serializes a batch to binary format.

  Note: The full Merkle tree is not serialized for storage efficiency.
  Use `deserialize/1` and then rebuild the tree if needed.
  """
  @spec serialize(t()) :: {:ok, binary()} | {:error, term()}
  def serialize(%__MODULE__{} = batch) do
    data = %{
      id: batch.id,
      event_ids: Enum.map(batch.events, & &1.id),
      event_hashes: Enum.map(batch.events, &Base.encode16(&1.hash, case: :lower)),
      merkle_root: Base.encode16(batch.merkle_root, case: :lower),
      created_at: DateTime.to_iso8601(batch.created_at),
      tx_hash: batch.tx_hash,
      block_number: batch.block_number,
      chain: batch.chain && Atom.to_string(batch.chain),
      status: batch.status && Atom.to_string(batch.status)
    }

    {:ok, Jason.encode!(data)}
  rescue
    e -> {:error, {:serialization_failed, e}}
  end

  # ============================================================================
  # Merkle Tree Implementation
  # ============================================================================

  defp build_merkle_tree(leaves) when length(leaves) == 0 do
    {[[]], <<0::256>>}
  end

  defp build_merkle_tree(leaves) do
    # Ensure leaves are hashed
    hashed_leaves =
      Enum.map(leaves, fn
        leaf when byte_size(leaf) == 32 -> leaf
        leaf -> hash(leaf)
      end)

    # Build tree bottom-up, storing all levels
    tree = build_tree_levels([hashed_leaves])
    root = hd(hd(tree))

    {tree, root}
  end

  defp build_tree_levels([[single]]) do
    [[single]]
  end

  defp build_tree_levels([current_level | _] = tree) when length(current_level) == 1 do
    tree
  end

  defp build_tree_levels([current_level | _] = tree) do
    # Pad to even number by duplicating last element
    padded =
      if rem(length(current_level), 2) == 1 do
        current_level ++ [List.last(current_level)]
      else
        current_level
      end

    # Combine pairs into parent nodes
    next_level =
      padded
      |> Enum.chunk_every(2)
      |> Enum.map(fn [left, right] -> hash_pair(left, right) end)

    build_tree_levels([next_level | tree])
  end

  defp compute_merkle_proof(tree, leaf_index) do
    # Tree is stored root-first, so reverse for bottom-up traversal
    # Drop the root level since we don't need a sibling there
    levels =
      tree
      |> Enum.reverse()
      |> Enum.drop(-1)

    {proof, _} =
      Enum.reduce(levels, {[], leaf_index}, fn level, {proof_acc, idx} ->
        # Determine sibling index
        sibling_idx = if rem(idx, 2) == 0, do: idx + 1, else: idx - 1

        # Get sibling (handle edge case where sibling doesn't exist)
        sibling = Enum.at(level, sibling_idx) || Enum.at(level, idx)

        # Direction: 0 = sibling is on right, 1 = sibling is on left
        direction = if rem(idx, 2) == 0, do: 0, else: 1

        # Parent index for next level
        parent_idx = div(idx, 2)

        # Store sibling with direction hint
        {[{sibling, direction} | proof_acc], parent_idx}
      end)

    Enum.reverse(proof)
  end

  defp compute_root_from_proof(leaf_hash, proof) do
    Enum.reduce(proof, leaf_hash, fn {sibling, direction}, current ->
      if direction == 0 do
        # Sibling is on right
        hash_pair(current, sibling)
      else
        # Sibling is on left
        hash_pair(sibling, current)
      end
    end)
  end

  defp hash_pair(left, right) do
    hash(left <> right)
  end

  defp hash(data), do: :crypto.hash(@hash_algorithm, data)

  defp secure_compare(a, b) when byte_size(a) == byte_size(b) do
    :crypto.hash_equals(a, b)
  end

  defp secure_compare(_, _), do: false
end
