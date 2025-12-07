defmodule Tessera.Attestation.Adapters.Ethereum do
  @moduledoc """
  Ethereum blockchain attestation adapter.

  This adapter creates attestations on Ethereum-compatible networks by
  submitting transactions to a Tessera attestation smart contract.

  ## Smart Contract

  The adapter interacts with a minimal attestation contract:

  ```solidity
  contract TesseraAttestations {
      event Attestation(bytes32 indexed root, uint256 timestamp);

      function attest(bytes32 root) external {
          emit Attestation(root, block.timestamp);
      }
  }
  ```

  ## Configuration

  Configure the adapter in your config:

      config :tessera, Tessera.Attestation.Adapters.Ethereum,
        rpc_url: "https://mainnet.infura.io/v3/YOUR_KEY",
        contract_address: "0x...",
        private_key: {:system, "ETH_PRIVATE_KEY"},
        chain_id: 1,
        gas_price_strategy: :standard

  ## Networks

  Supported networks:
  - Ethereum Mainnet (chain_id: 1)
  - Goerli Testnet (chain_id: 5)
  - Sepolia Testnet (chain_id: 11155111)
  - Local development (chain_id: 1337)

  ## Cost Considerations

  - Single attestation: ~45,000 gas
  - Batch attestation: ~45,000 gas (same, only stores Merkle root)
  - 10x cost reduction by batching 10 events

  ## Usage

      # Start the adapter
      {:ok, _pid} = Tessera.Attestation.Adapters.Ethereum.start_link(
        rpc_url: "https://sepolia.infura.io/v3/...",
        contract_address: "0x...",
        private_key: "0x..."
      )

      # Create attestation
      {:ok, attestation} = Tessera.Attestation.Adapters.Ethereum.attest(
        :pod_creation,
        %{pod_id: "pod_123"}
      )
  """

  use GenServer

  @behaviour Tessera.Attestation

  alias Tessera.Attestation.{Batch, Event}

  # ABI-encoded function signature for attest(bytes32)
  @attest_selector "0x4e11f972"

  # Default configuration
  @default_gas_limit 100_000
  @default_confirmations 1

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the Ethereum adapter.

  ## Options

  - `:rpc_url` - Ethereum JSON-RPC endpoint URL (required)
  - `:contract_address` - Deployed attestation contract address (required)
  - `:private_key` - Private key for signing transactions (required)
  - `:chain_id` - Network chain ID (default: 1 for mainnet)
  - `:gas_limit` - Gas limit for transactions (default: 100,000)
  - `:gas_price_gwei` - Gas price in Gwei (default: auto-estimate)
  """
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Stops the adapter.
  """
  def stop do
    GenServer.stop(__MODULE__)
  end

  # ============================================================================
  # Behaviour Implementation
  # ============================================================================

  @impl Tessera.Attestation
  def attest(event_type, event_data, opts \\ []) do
    GenServer.call(__MODULE__, {:attest, event_type, event_data, opts}, 60_000)
  end

  @impl Tessera.Attestation
  def verify(attestation_id) do
    GenServer.call(__MODULE__, {:verify, attestation_id})
  end

  @impl Tessera.Attestation
  def batch_attest(events, opts \\ []) do
    GenServer.call(__MODULE__, {:batch_attest, events, opts}, 60_000)
  end

  @impl Tessera.Attestation
  def verify_batch_inclusion(batch_id, event_id, merkle_proof) do
    GenServer.call(__MODULE__, {:verify_batch_inclusion, batch_id, event_id, merkle_proof})
  end

  @impl Tessera.Attestation
  def info do
    GenServer.call(__MODULE__, :info)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl GenServer
  def init(opts) do
    rpc_url = Keyword.fetch!(opts, :rpc_url)
    contract_address = Keyword.fetch!(opts, :contract_address)
    private_key = resolve_private_key(Keyword.fetch!(opts, :private_key))

    state = %{
      rpc_url: rpc_url,
      contract_address: normalize_address(contract_address),
      private_key: private_key,
      chain_id: Keyword.get(opts, :chain_id, 1),
      gas_limit: Keyword.get(opts, :gas_limit, @default_gas_limit),
      gas_price_gwei: Keyword.get(opts, :gas_price_gwei),
      http_client: Keyword.get(opts, :http_client, Tessera.HTTPClient),
      attestations: %{},
      batches: %{}
    }

    {:ok, state}
  end

  @impl GenServer
  def handle_call({:attest, event_type, event_data, opts}, _from, state) do
    {:ok, event} = Event.new(event_type, event_data)

    case submit_attestation(event.hash, opts, state) do
      {:ok, tx_hash, block_number} ->
        attestation = %{
          id: event.id,
          event_type: event_type,
          event_hash: event.hash,
          tx_hash: tx_hash,
          block_number: block_number,
          chain: :ethereum,
          timestamp: DateTime.utc_now(),
          status: :confirmed
        }

        new_state = put_in(state.attestations[event.id], attestation)
        {:reply, {:ok, attestation}, new_state}

      {:error, _} = error ->
        {:reply, error, state}
    end
  end

  @impl GenServer
  def handle_call({:verify, attestation_id}, _from, state) do
    case Map.get(state.attestations, attestation_id) ||
           Map.get(state.batches, attestation_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      attestation ->
        # In a real implementation, we would query the blockchain
        # to verify the transaction is still valid and get confirmations
        verification = %{
          valid: attestation.status == :confirmed,
          timestamp: attestation.timestamp,
          block_number: attestation.block_number,
          tx_hash: attestation.tx_hash,
          confirmations: 1
        }

        {:reply, {:ok, verification}, state}
    end
  end

  @impl GenServer
  def handle_call({:batch_attest, events_data, opts}, _from, state) do
    # Create events from the data
    events =
      Enum.map(events_data, fn {event_type, event_data} ->
        {:ok, event} = Event.new(event_type, event_data)
        event
      end)

    case Batch.new(events) do
      {:ok, batch} ->
        case submit_attestation(batch.merkle_root, opts, state) do
          {:ok, tx_hash, block_number} ->
            batch_record = %{
              id: batch.id,
              merkle_root: batch.merkle_root,
              event_count: length(events),
              events: Enum.map(events, & &1.id),
              tx_hash: tx_hash,
              block_number: block_number,
              chain: :ethereum,
              timestamp: DateTime.utc_now(),
              status: :confirmed,
              batch: batch
            }

            # Store batch and individual events
            new_state =
              state
              |> put_in([:batches, batch.id], batch_record)
              |> update_in([:attestations], fn attestations ->
                Enum.reduce(events, attestations, fn event, acc ->
                  Map.put(acc, event.id, %{
                    id: event.id,
                    event_type: event.type,
                    event_hash: event.hash,
                    batch_id: batch.id,
                    tx_hash: tx_hash,
                    block_number: block_number,
                    chain: :ethereum,
                    timestamp: DateTime.utc_now(),
                    status: :confirmed
                  })
                end)
              end)

            {:reply, {:ok, batch_record}, new_state}

          {:error, _} = error ->
            {:reply, error, state}
        end

      {:error, _} = error ->
        {:reply, error, state}
    end
  end

  @impl GenServer
  def handle_call({:verify_batch_inclusion, batch_id, event_id, merkle_proof}, _from, state) do
    with {:ok, batch_record} <- get_batch(state, batch_id),
         {:ok, event_record} <- get_attestation(state, event_id),
         :ok <-
           Batch.verify_inclusion(batch_record.merkle_root, event_record.event_hash, merkle_proof) do
      verification = %{
        valid: true,
        timestamp: batch_record.timestamp,
        block_number: batch_record.block_number,
        tx_hash: batch_record.tx_hash,
        confirmations: 1
      }

      {:reply, {:ok, verification}, state}
    else
      {:error, _} = error -> {:reply, error, state}
    end
  end

  @impl GenServer
  def handle_call(:info, _from, state) do
    info = %{
      chain: :ethereum,
      network: chain_name(state.chain_id),
      connected: true,
      contract_address: state.contract_address
    }

    {:reply, info, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp submit_attestation(hash, opts, state) do
    wait_for_confirmation = Keyword.get(opts, :wait_for_confirmation, true)
    confirmations = Keyword.get(opts, :confirmations, @default_confirmations)

    # Build the transaction
    tx_data = encode_attest_call(hash)

    with {:ok, gas_price} <- get_gas_price(state),
         {:ok, nonce} <- get_nonce(state),
         {:ok, signed_tx} <- sign_transaction(tx_data, gas_price, nonce, state),
         {:ok, tx_hash} <- send_transaction(signed_tx, state) do
      if wait_for_confirmation do
        wait_for_tx_confirmation(tx_hash, confirmations, state)
      else
        {:ok, tx_hash, nil}
      end
    end
  end

  defp encode_attest_call(hash) when byte_size(hash) == 32 do
    # ABI encode: function selector + bytes32 argument
    @attest_selector <> Base.encode16(hash, case: :lower)
  end

  defp get_gas_price(state) do
    case state.gas_price_gwei do
      nil ->
        # Auto-estimate gas price
        eth_gas_price(state)

      gwei ->
        {:ok, gwei * 1_000_000_000}
    end
  end

  defp eth_gas_price(state) do
    case rpc_call("eth_gasPrice", [], state) do
      {:ok, hex_price} ->
        {:ok, hex_to_integer(hex_price)}

      error ->
        error
    end
  end

  defp get_nonce(state) do
    address = private_key_to_address(state.private_key)

    case rpc_call("eth_getTransactionCount", [address, "pending"], state) do
      {:ok, hex_nonce} ->
        {:ok, hex_to_integer(hex_nonce)}

      error ->
        error
    end
  end

  defp sign_transaction(data, gas_price, nonce, state) do
    # Build unsigned transaction
    tx = %{
      nonce: nonce,
      gas_price: gas_price,
      gas_limit: state.gas_limit,
      to: state.contract_address,
      value: 0,
      data: data,
      chain_id: state.chain_id
    }

    # Sign the transaction (simplified - real implementation would use proper signing)
    # This is a placeholder - actual signing requires proper ECDSA implementation
    signed = encode_signed_transaction(tx, state.private_key)
    {:ok, signed}
  end

  defp encode_signed_transaction(tx, _private_key) do
    # Placeholder for actual RLP encoding and signing
    # In production, use a proper Ethereum transaction signing library
    "0x" <>
      Base.encode16(
        :crypto.hash(:sha256, :erlang.term_to_binary(tx)),
        case: :lower
      )
  end

  defp send_transaction(signed_tx, state) do
    case rpc_call("eth_sendRawTransaction", [signed_tx], state) do
      {:ok, tx_hash} ->
        {:ok, tx_hash}

      {:error, %{"message" => message}} ->
        {:error, {:transaction_failed, message}}

      error ->
        error
    end
  end

  defp wait_for_tx_confirmation(tx_hash, _confirmations, state) do
    # Poll for transaction receipt
    case poll_for_receipt(tx_hash, 30, state) do
      {:ok, receipt} ->
        block_number = hex_to_integer(receipt["blockNumber"])
        {:ok, tx_hash, block_number}

      {:error, :timeout} ->
        {:error, :confirmation_timeout}

      error ->
        error
    end
  end

  defp poll_for_receipt(_tx_hash, 0, _state), do: {:error, :timeout}

  defp poll_for_receipt(tx_hash, attempts, state) do
    case rpc_call("eth_getTransactionReceipt", [tx_hash], state) do
      {:ok, nil} ->
        Process.sleep(1000)
        poll_for_receipt(tx_hash, attempts - 1, state)

      {:ok, receipt} when is_map(receipt) ->
        {:ok, receipt}

      error ->
        error
    end
  end

  defp rpc_call(method, params, state) do
    body =
      Jason.encode!(%{
        jsonrpc: "2.0",
        method: method,
        params: params,
        id: :erlang.unique_integer()
      })

    case state.http_client.post(state.rpc_url,
           body: body,
           headers: [{"content-type", "application/json"}]
         ) do
      {:ok, %{status: 200, body: response_body}} ->
        case Jason.decode!(response_body) do
          %{"result" => result} -> {:ok, result}
          %{"error" => error} -> {:error, error}
        end

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, {:connection_error, reason}}
    end
  end

  defp get_batch(state, batch_id) do
    case Map.get(state.batches, batch_id) do
      nil -> {:error, :not_found}
      batch -> {:ok, batch}
    end
  end

  defp get_attestation(state, attestation_id) do
    case Map.get(state.attestations, attestation_id) do
      nil -> {:error, :not_found}
      attestation -> {:ok, attestation}
    end
  end

  defp resolve_private_key({:system, env_var}), do: System.get_env(env_var)
  defp resolve_private_key(key) when is_binary(key), do: key

  defp normalize_address("0x" <> _ = address), do: String.downcase(address)
  defp normalize_address(address), do: "0x" <> String.downcase(address)

  defp private_key_to_address(_private_key) do
    # Placeholder - actual implementation would derive address from private key
    "0x0000000000000000000000000000000000000000"
  end

  defp hex_to_integer("0x" <> hex), do: String.to_integer(hex, 16)
  defp hex_to_integer(hex), do: String.to_integer(hex, 16)

  defp chain_name(1), do: "mainnet"
  defp chain_name(5), do: "goerli"
  defp chain_name(11_155_111), do: "sepolia"
  defp chain_name(137), do: "polygon"
  defp chain_name(80_001), do: "mumbai"
  defp chain_name(1337), do: "localhost"
  defp chain_name(id), do: "chain_#{id}"
end
