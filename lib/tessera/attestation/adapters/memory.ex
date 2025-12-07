defmodule Tessera.Attestation.Adapters.Memory do
  @moduledoc """
  In-memory attestation adapter for testing and development.

  This adapter simulates blockchain attestation without actual chain
  interaction. All attestations are stored in an ETS table and can be
  queried and verified as if they were on-chain.

  ## Usage

      # Start the adapter (usually done in test setup)
      {:ok, _pid} = Tessera.Attestation.Adapters.Memory.start_link()

      # Create attestation
      {:ok, attestation} = Tessera.Attestation.Adapters.Memory.attest(
        :pod_creation,
        %{pod_id: "test_pod"}
      )

      # Verify
      {:ok, verification} = Tessera.Attestation.Adapters.Memory.verify(attestation.id)

  ## Configuration

  The adapter can be configured to simulate delays and failures:

      Tessera.Attestation.Adapters.Memory.configure(
        simulated_delay_ms: 100,
        failure_rate: 0.1
      )
  """

  use GenServer

  @behaviour Tessera.Attestation

  alias Tessera.Attestation.{Batch, Event}

  @table_name :tessera_attestation_memory

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the memory adapter.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Stops the memory adapter.
  """
  def stop do
    GenServer.stop(__MODULE__)
  end

  @doc """
  Clears all stored attestations.
  """
  def clear do
    GenServer.call(__MODULE__, :clear)
  end

  @doc """
  Returns all stored attestations.
  """
  def all do
    GenServer.call(__MODULE__, :all)
  end

  @doc """
  Configures the adapter behavior.

  ## Options

  - `:simulated_delay_ms` - Add artificial delay to operations
  - `:failure_rate` - Probability of simulated failures (0.0 to 1.0)
  - `:block_time_ms` - Simulated block time (default: 0, instant)
  """
  def configure(opts) do
    GenServer.call(__MODULE__, {:configure, opts})
  end

  # ============================================================================
  # Behaviour Implementation
  # ============================================================================

  @impl Tessera.Attestation
  def attest(event_type, event_data, opts \\ []) do
    GenServer.call(__MODULE__, {:attest, event_type, event_data, opts})
  end

  @impl Tessera.Attestation
  def verify(attestation_id) do
    GenServer.call(__MODULE__, {:verify, attestation_id})
  end

  @impl Tessera.Attestation
  def batch_attest(events, opts \\ []) do
    GenServer.call(__MODULE__, {:batch_attest, events, opts})
  end

  @impl Tessera.Attestation
  def verify_batch_inclusion(batch_id, event_id, merkle_proof) do
    GenServer.call(__MODULE__, {:verify_batch_inclusion, batch_id, event_id, merkle_proof})
  end

  @impl Tessera.Attestation
  def info do
    %{
      chain: :memory,
      network: "local",
      connected: true,
      contract_address: nil
    }
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl GenServer
  def init(_opts) do
    table = :ets.new(@table_name, [:set, :named_table, :public])

    state = %{
      table: table,
      block_number: 1,
      config: %{
        simulated_delay_ms: 0,
        failure_rate: 0.0,
        block_time_ms: 0
      }
    }

    {:ok, state}
  end

  @impl GenServer
  def handle_call(:clear, _from, state) do
    :ets.delete_all_objects(state.table)
    {:reply, :ok, %{state | block_number: 1}}
  end

  @impl GenServer
  def handle_call(:all, _from, state) do
    attestations =
      :ets.tab2list(state.table)
      |> Enum.map(fn {_id, attestation} -> attestation end)

    {:reply, attestations, state}
  end

  @impl GenServer
  def handle_call({:configure, opts}, _from, state) do
    new_config = Map.merge(state.config, Map.new(opts))
    {:reply, :ok, %{state | config: new_config}}
  end

  @impl GenServer
  def handle_call({:attest, event_type, event_data, opts}, _from, state) do
    maybe_delay(state.config)

    case maybe_fail(state.config) do
      :ok ->
        result = do_attest(event_type, event_data, opts, state)
        {:reply, result, increment_block(state)}

      {:error, _} = error ->
        {:reply, error, state}
    end
  end

  @impl GenServer
  def handle_call({:verify, attestation_id}, _from, state) do
    maybe_delay(state.config)

    result =
      case :ets.lookup(state.table, attestation_id) do
        [{^attestation_id, attestation}] ->
          verification = %{
            valid: true,
            timestamp: attestation.timestamp,
            block_number: attestation.block_number,
            tx_hash: attestation.tx_hash,
            confirmations: state.block_number - attestation.block_number
          }

          {:ok, verification}

        [] ->
          {:error, :not_found}
      end

    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:batch_attest, events_data, opts}, _from, state) do
    maybe_delay(state.config)

    case maybe_fail(state.config) do
      :ok ->
        result = do_batch_attest(events_data, opts, state)
        {:reply, result, increment_block(state)}

      {:error, _} = error ->
        {:reply, error, state}
    end
  end

  @impl GenServer
  def handle_call({:verify_batch_inclusion, batch_id, event_id, merkle_proof}, _from, state) do
    result =
      case :ets.lookup(state.table, batch_id) do
        [{^batch_id, %{type: :batch} = batch_record}] ->
          # Find the event in our records
          case :ets.lookup(state.table, event_id) do
            [{^event_id, event_record}] ->
              # Verify the Merkle proof
              case Batch.verify_inclusion(
                     batch_record.merkle_root,
                     event_record.event_hash,
                     merkle_proof
                   ) do
                :ok ->
                  {:ok,
                   %{
                     valid: true,
                     timestamp: batch_record.timestamp,
                     block_number: batch_record.block_number,
                     tx_hash: batch_record.tx_hash,
                     confirmations: state.block_number - batch_record.block_number
                   }}

                {:error, :invalid_proof} ->
                  {:error, :invalid_proof}
              end

            [] ->
              {:error, :not_found}
          end

        [] ->
          {:error, :not_found}
      end

    {:reply, result, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp do_attest(event_type, event_data, _opts, state) do
    {:ok, event} = Event.new(event_type, event_data)

    tx_hash = generate_tx_hash()

    attestation = %{
      id: event.id,
      type: :single,
      event_type: event_type,
      event_hash: event.hash,
      tx_hash: tx_hash,
      block_number: state.block_number,
      chain: :memory,
      timestamp: DateTime.utc_now(),
      status: :confirmed
    }

    :ets.insert(state.table, {event.id, attestation})

    {:ok, attestation}
  end

  defp do_batch_attest(events_data, _opts, state) do
    # Create events from the data
    events =
      Enum.map(events_data, fn {event_type, event_data} ->
        {:ok, event} = Event.new(event_type, event_data)
        event
      end)

    # Create the batch
    case Batch.new(events) do
      {:ok, batch} ->
        tx_hash = generate_tx_hash()

        # Store the batch record
        batch_record = %{
          id: batch.id,
          type: :batch,
          merkle_root: batch.merkle_root,
          event_count: length(events),
          event_ids: Enum.map(events, & &1.id),
          tx_hash: tx_hash,
          block_number: state.block_number,
          chain: :memory,
          timestamp: DateTime.utc_now(),
          status: :confirmed
        }

        :ets.insert(state.table, {batch.id, batch_record})

        # Store individual event records
        Enum.each(events, fn event ->
          event_record = %{
            id: event.id,
            type: :batch_event,
            event_type: event.type,
            event_hash: event.hash,
            batch_id: batch.id,
            tx_hash: tx_hash,
            block_number: state.block_number,
            chain: :memory,
            timestamp: DateTime.utc_now(),
            status: :confirmed
          }

          :ets.insert(state.table, {event.id, event_record})
        end)

        # Return the batch with proof generation capability
        {:ok, Map.put(batch_record, :batch, batch)}

      {:error, _} = error ->
        error
    end
  end

  defp generate_tx_hash do
    bytes = :crypto.strong_rand_bytes(32)
    "0x" <> Base.encode16(bytes, case: :lower)
  end

  defp maybe_delay(%{simulated_delay_ms: delay}) when delay > 0 do
    Process.sleep(delay)
  end

  defp maybe_delay(_), do: :ok

  defp maybe_fail(%{failure_rate: rate}) when rate > 0 do
    if :rand.uniform() < rate do
      {:error, :simulated_failure}
    else
      :ok
    end
  end

  defp maybe_fail(_), do: :ok

  defp increment_block(state) do
    %{state | block_number: state.block_number + 1}
  end
end
