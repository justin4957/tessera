defmodule Tessera.Attestation do
  @moduledoc """
  Blockchain attestation for anchoring temporal proofs to immutable ledgers.

  This module provides a behaviour for creating and verifying attestations
  on various blockchain networks. Attestations anchor pod events to public
  verifiable records, providing cryptographic evidence of when events occurred.

  ## Supported Chains

  - Ethereum (mainnet and testnets)
  - Polygon (lower cost alternative)
  - Memory (for testing)

  ## Attestation Types

  - `:pod_creation` - Pod lifecycle events
  - `:grant_issuance` - Grant creation and revocation
  - `:consensus_outcome` - Pod consensus results
  - `:key_rotation` - Epoch key rotation events
  - `:epoch_boundary` - Epoch transition markers

  ## Usage

      # Single attestation
      {:ok, attestation} = Tessera.Attestation.attest(adapter, :pod_creation, %{
        pod_id: "pod_123",
        creator: "did:key:...",
        timestamp: DateTime.utc_now()
      })

      # Batch attestation for cost efficiency
      {:ok, batch} = Tessera.Attestation.batch_attest(adapter, [
        {:grant_issuance, %{grant_id: "g1", ...}},
        {:grant_issuance, %{grant_id: "g2", ...}}
      ])

      # Verify attestation on chain
      {:ok, verification} = Tessera.Attestation.verify(adapter, attestation.id)

  ## Data Privacy

  Only cryptographic hashes are stored on-chain. The actual event data
  remains private and can be revealed selectively for verification.
  """

  # ============================================================================
  # Types
  # ============================================================================

  @type attestation_id :: String.t()
  @type tx_hash :: String.t()
  @type block_number :: non_neg_integer()
  @type chain :: :ethereum | :polygon | :memory | atom()

  @type event_type ::
          :pod_creation
          | :grant_issuance
          | :grant_revocation
          | :consensus_outcome
          | :key_rotation
          | :epoch_boundary

  @type attestation :: %{
          id: attestation_id(),
          event_type: event_type(),
          event_hash: binary(),
          tx_hash: tx_hash() | nil,
          block_number: block_number() | nil,
          chain: chain(),
          timestamp: DateTime.t(),
          status: :pending | :confirmed | :failed
        }

  @type verification :: %{
          valid: boolean(),
          timestamp: DateTime.t(),
          block_number: block_number(),
          tx_hash: tx_hash(),
          confirmations: non_neg_integer()
        }

  @type batch_attestation :: %{
          id: attestation_id(),
          merkle_root: binary(),
          event_count: non_neg_integer(),
          events: [attestation_id()],
          tx_hash: tx_hash() | nil,
          block_number: block_number() | nil,
          chain: chain(),
          timestamp: DateTime.t(),
          status: :pending | :confirmed | :failed
        }

  @type error :: {:error, term()}

  # ============================================================================
  # Behaviour Callbacks
  # ============================================================================

  @doc """
  Creates an attestation for a single event.

  The event data is hashed and the hash is submitted to the blockchain.
  Returns the attestation with transaction details.

  ## Options

  - `:wait_for_confirmation` - Wait for transaction confirmation (default: false)
  - `:confirmations` - Number of confirmations to wait for (default: 1)
  - `:gas_price` - Custom gas price (chain-specific)
  """
  @callback attest(event_type(), event_data :: map(), opts :: keyword()) ::
              {:ok, attestation()} | error()

  @doc """
  Verifies an attestation exists on chain.

  Returns verification details including block timestamp and confirmations.
  """
  @callback verify(attestation_id()) ::
              {:ok, verification()} | {:error, :not_found} | error()

  @doc """
  Creates a batch attestation using a Merkle tree.

  Multiple events are combined into a single Merkle root, which is then
  attested on-chain. This reduces costs by ~10x compared to individual
  attestations.

  ## Options

  Same as `attest/3` plus:
  - `:max_batch_size` - Maximum events per batch (default: 100)
  """
  @callback batch_attest([{event_type(), map()}], opts :: keyword()) ::
              {:ok, batch_attestation()} | error()

  @doc """
  Verifies that an event is included in a batch attestation.

  Requires the Merkle proof for the specific event.
  """
  @callback verify_batch_inclusion(
              batch_id :: attestation_id(),
              event_id :: attestation_id(),
              merkle_proof :: [binary()]
            ) ::
              {:ok, verification()} | {:error, :not_found | :invalid_proof} | error()

  @doc """
  Returns information about the adapter and chain connection.
  """
  @callback info() :: %{
              chain: chain(),
              network: String.t(),
              connected: boolean(),
              contract_address: String.t() | nil
            }

  @optional_callbacks []

  # ============================================================================
  # Public API (Delegates to Adapter)
  # ============================================================================

  @doc """
  Creates an attestation using the specified adapter.
  """
  @spec attest(module(), event_type(), map(), keyword()) :: {:ok, attestation()} | error()
  def attest(adapter, event_type, event_data, opts \\ []) do
    adapter.attest(event_type, event_data, opts)
  end

  @doc """
  Verifies an attestation using the specified adapter.
  """
  @spec verify(module(), attestation_id()) :: {:ok, verification()} | error()
  def verify(adapter, attestation_id) do
    adapter.verify(attestation_id)
  end

  @doc """
  Creates a batch attestation using the specified adapter.
  """
  @spec batch_attest(module(), [{event_type(), map()}], keyword()) ::
          {:ok, batch_attestation()} | error()
  def batch_attest(adapter, events, opts \\ []) do
    adapter.batch_attest(events, opts)
  end

  @doc """
  Verifies batch inclusion using the specified adapter.
  """
  @spec verify_batch_inclusion(module(), attestation_id(), attestation_id(), [binary()]) ::
          {:ok, verification()} | error()
  def verify_batch_inclusion(adapter, batch_id, event_id, merkle_proof) do
    adapter.verify_batch_inclusion(batch_id, event_id, merkle_proof)
  end

  @doc """
  Returns adapter information.
  """
  @spec info(module()) :: map()
  def info(adapter) do
    adapter.info()
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  @doc """
  Generates a unique attestation ID.
  """
  @spec generate_id() :: attestation_id()
  def generate_id do
    bytes = :crypto.strong_rand_bytes(16)
    Base.encode16(bytes, case: :lower)
  end

  @doc """
  Computes the hash of event data for attestation.

  Uses SHA-256 with domain separation to prevent cross-protocol attacks.
  """
  @spec hash_event(event_type(), map()) :: binary()
  def hash_event(event_type, event_data) do
    domain = "Tessera.Attestation.Event.v1"
    type_binary = Atom.to_string(event_type)
    data_binary = :erlang.term_to_binary(event_data)

    :crypto.hash(:sha256, [
      domain,
      <<byte_size(type_binary)::32>>,
      type_binary,
      <<byte_size(data_binary)::32>>,
      data_binary
    ])
  end

  @doc """
  Validates that an event type is supported.
  """
  @spec valid_event_type?(atom()) :: boolean()
  def valid_event_type?(type)
      when type in [
             :pod_creation,
             :grant_issuance,
             :grant_revocation,
             :consensus_outcome,
             :key_rotation,
             :epoch_boundary
           ],
      do: true

  def valid_event_type?(_), do: false
end
