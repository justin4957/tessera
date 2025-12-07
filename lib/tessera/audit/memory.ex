defmodule Tessera.Audit.Memory do
  @moduledoc """
  In-memory audit log adapter using ETS.

  Provides fast, in-memory storage for audit entries with hash chaining.
  Data does not persist across process restarts.

  ## Usage

      # Start the audit log
      {:ok, _pid} = Tessera.Audit.Memory.start_link()

      # Log an event
      {:ok, entry} = Tessera.Audit.Memory.log_event(:grant_created, %{
        actor_id: "did:web:alice.example",
        grant_id: "g_123"
      })

      # Query events
      {:ok, events} = Tessera.Audit.Memory.query_events(
        event_type: :grant_created,
        from: ~U[2024-01-01 00:00:00Z]
      )

      # Verify chain integrity
      :ok = Tessera.Audit.Memory.verify_chain(~U[2024-01-01 00:00:00Z], ~U[2024-12-31 23:59:59Z])

  ## Indexes

  The adapter maintains secondary indexes for:
  - Event type -> [Entry ID]
  - Actor ID -> [Entry ID]
  - Resource ID -> [Entry ID]
  - Timestamp (ordered for range queries)
  """

  use GenServer

  @behaviour Tessera.Audit

  alias Tessera.Audit.Entry

  @entries_table :tessera_audit_entries
  @type_index :tessera_audit_by_type
  @actor_index :tessera_audit_by_actor
  @resource_index :tessera_audit_by_resource
  @sequence_table :tessera_audit_sequence

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the memory audit log.

  ## Options

  - `:name` - GenServer name (default: `__MODULE__`)
  - `:table_prefix` - Prefix for ETS table names (for testing isolation)
  """
  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Stops the audit log.
  """
  def stop(server \\ __MODULE__) do
    GenServer.stop(server)
  end

  @doc """
  Clears all audit entries and resets the chain.
  """
  def clear(server \\ __MODULE__) do
    GenServer.call(server, :clear)
  end

  # ============================================================================
  # Audit Behaviour Implementation
  # ============================================================================

  @impl Tessera.Audit
  def log_event(event_type, details, server \\ __MODULE__) do
    GenServer.call(server, {:log_event, event_type, details})
  end

  @impl Tessera.Audit
  def query_events(opts \\ [], server \\ __MODULE__) do
    GenServer.call(server, {:query_events, opts})
  end

  @impl Tessera.Audit
  def get_entry(entry_id, server \\ __MODULE__) do
    GenServer.call(server, {:get_entry, entry_id})
  end

  @impl Tessera.Audit
  def verify_chain(from, to, server \\ __MODULE__) do
    GenServer.call(server, {:verify_chain, from, to})
  end

  @impl Tessera.Audit
  def chain_head(server \\ __MODULE__) do
    GenServer.call(server, :chain_head)
  end

  @impl Tessera.Audit
  def info(server \\ __MODULE__) do
    GenServer.call(server, :info)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl GenServer
  def init(opts) do
    table_prefix = Keyword.get(opts, :table_prefix, "")

    entries_table = table_name(@entries_table, table_prefix)
    type_index = table_name(@type_index, table_prefix)
    actor_index = table_name(@actor_index, table_prefix)
    resource_index = table_name(@resource_index, table_prefix)
    sequence_table = table_name(@sequence_table, table_prefix)

    # Create ETS tables
    :ets.new(entries_table, [:set, :named_table, :protected])
    :ets.new(type_index, [:bag, :named_table, :protected])
    :ets.new(actor_index, [:bag, :named_table, :protected])
    :ets.new(resource_index, [:bag, :named_table, :protected])
    :ets.new(sequence_table, [:ordered_set, :named_table, :protected])

    state = %{
      entries_table: entries_table,
      type_index: type_index,
      actor_index: actor_index,
      resource_index: resource_index,
      sequence_table: sequence_table,
      chain_head: nil,
      sequence_counter: 0
    }

    {:ok, state}
  end

  @impl GenServer
  def handle_call(:clear, _from, state) do
    :ets.delete_all_objects(state.entries_table)
    :ets.delete_all_objects(state.type_index)
    :ets.delete_all_objects(state.actor_index)
    :ets.delete_all_objects(state.resource_index)
    :ets.delete_all_objects(state.sequence_table)

    new_state = %{state | chain_head: nil, sequence_counter: 0}
    {:reply, :ok, new_state}
  end

  @impl GenServer
  def handle_call({:log_event, event_type, details}, _from, state) do
    actor_id = Map.get(details, :actor_id)
    resource_id = Map.get(details, :resource_id)
    sequence_number = state.sequence_counter + 1

    entry =
      Entry.new(
        event_type: event_type,
        actor_id: actor_id,
        resource_id: resource_id,
        details: details,
        previous_hash: state.chain_head,
        sequence_number: sequence_number
      )

    # Store entry
    :ets.insert(state.entries_table, {entry.id, entry})

    # Update indexes
    :ets.insert(state.type_index, {event_type, entry.id})

    if actor_id do
      :ets.insert(state.actor_index, {actor_id, entry.id})
    end

    if resource_id do
      :ets.insert(state.resource_index, {resource_id, entry.id})
    end

    # Store in sequence table for ordered queries
    :ets.insert(state.sequence_table, {sequence_number, entry.id})

    new_state = %{
      state
      | chain_head: entry.entry_hash,
        sequence_counter: sequence_number
    }

    {:reply, {:ok, entry}, new_state}
  end

  @impl GenServer
  def handle_call({:query_events, opts}, _from, state) do
    entries = do_query_events(opts, state)
    {:reply, {:ok, entries}, state}
  end

  @impl GenServer
  def handle_call({:get_entry, entry_id}, _from, state) do
    result =
      case :ets.lookup(state.entries_table, entry_id) do
        [{^entry_id, entry}] -> {:ok, entry}
        [] -> {:error, :not_found}
      end

    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:verify_chain, from, to}, _from, state) do
    result = do_verify_chain(from, to, state)
    {:reply, result, state}
  end

  @impl GenServer
  def handle_call(:chain_head, _from, state) do
    {:reply, {:ok, state.chain_head}, state}
  end

  @impl GenServer
  def handle_call(:info, _from, state) do
    count = :ets.info(state.entries_table, :size)

    {oldest, newest} = get_timestamp_range(state)

    info = %{
      type: :memory,
      entry_count: count,
      chain_head: state.chain_head,
      oldest_entry: oldest,
      newest_entry: newest,
      persistent: false,
      capabilities: [
        :log_event,
        :query_events,
        :verify_chain,
        :query_by_type,
        :query_by_actor,
        :query_by_resource,
        :time_range_queries
      ]
    }

    {:reply, info, state}
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp table_name(base, ""), do: base
  defp table_name(base, prefix), do: :"#{prefix}_#{base}"

  defp do_query_events(opts, state) do
    # Start with all entries or filter by index
    entry_ids = get_candidate_entry_ids(opts, state)

    # Fetch entries
    entries =
      entry_ids
      |> Enum.map(fn id ->
        case :ets.lookup(state.entries_table, id) do
          [{^id, entry}] -> entry
          [] -> nil
        end
      end)
      |> Enum.reject(&is_nil/1)

    # Apply filters
    entries
    |> filter_by_event_type(Keyword.get(opts, :event_type))
    |> filter_by_actor(Keyword.get(opts, :actor_id))
    |> filter_by_resource(Keyword.get(opts, :resource_id))
    |> filter_by_time_range(Keyword.get(opts, :from), Keyword.get(opts, :to))
    |> sort_by_timestamp()
    |> apply_pagination(Keyword.get(opts, :offset), Keyword.get(opts, :limit))
  end

  defp get_candidate_entry_ids(opts, state) do
    cond do
      # If filtering by event type, use type index
      type = Keyword.get(opts, :event_type) ->
        if is_list(type) do
          Enum.flat_map(type, fn t ->
            :ets.lookup(state.type_index, t) |> Enum.map(fn {_, id} -> id end)
          end)
        else
          :ets.lookup(state.type_index, type) |> Enum.map(fn {_, id} -> id end)
        end

      # If filtering by actor, use actor index
      actor = Keyword.get(opts, :actor_id) ->
        :ets.lookup(state.actor_index, actor) |> Enum.map(fn {_, id} -> id end)

      # If filtering by resource, use resource index
      resource = Keyword.get(opts, :resource_id) ->
        :ets.lookup(state.resource_index, resource) |> Enum.map(fn {_, id} -> id end)

      # Otherwise, get all entry IDs in order
      true ->
        :ets.foldl(
          fn {_seq, id}, acc -> [id | acc] end,
          [],
          state.sequence_table
        )
        |> Enum.reverse()
    end
  end

  defp filter_by_event_type(entries, nil), do: entries

  defp filter_by_event_type(entries, types) when is_list(types) do
    Enum.filter(entries, fn entry -> entry.event_type in types end)
  end

  defp filter_by_event_type(entries, type) do
    Enum.filter(entries, fn entry -> entry.event_type == type end)
  end

  defp filter_by_actor(entries, nil), do: entries

  defp filter_by_actor(entries, actor_id) do
    Enum.filter(entries, fn entry -> entry.actor_id == actor_id end)
  end

  defp filter_by_resource(entries, nil), do: entries

  defp filter_by_resource(entries, resource_id) do
    Enum.filter(entries, fn entry -> entry.resource_id == resource_id end)
  end

  defp filter_by_time_range(entries, nil, nil), do: entries

  defp filter_by_time_range(entries, from, to) do
    Enum.filter(entries, fn entry ->
      in_range?(entry.timestamp, from, to)
    end)
  end

  defp in_range?(timestamp, from, to) do
    after_from =
      case from do
        nil -> true
        dt -> DateTime.compare(timestamp, dt) in [:gt, :eq]
      end

    before_to =
      case to do
        nil -> true
        dt -> DateTime.compare(timestamp, dt) in [:lt, :eq]
      end

    after_from and before_to
  end

  defp sort_by_timestamp(entries) do
    Enum.sort(entries, fn a, b ->
      case Entry.compare(a, b) do
        :lt -> true
        :eq -> true
        :gt -> false
      end
    end)
  end

  defp apply_pagination(entries, nil, nil), do: entries

  defp apply_pagination(entries, offset, limit) do
    entries
    |> maybe_drop(offset)
    |> maybe_take(limit)
  end

  defp maybe_drop(entries, nil), do: entries
  defp maybe_drop(entries, offset), do: Enum.drop(entries, offset)

  defp maybe_take(entries, nil), do: entries
  defp maybe_take(entries, limit), do: Enum.take(entries, limit)

  defp do_verify_chain(from, to, state) do
    # Get entries in the time range, sorted by sequence
    entries =
      :ets.foldl(
        fn {_seq, id}, acc ->
          case :ets.lookup(state.entries_table, id) do
            [{^id, entry}] ->
              if in_range?(entry.timestamp, from, to) do
                [entry | acc]
              else
                acc
              end

            [] ->
              acc
          end
        end,
        [],
        state.sequence_table
      )
      |> Enum.reverse()
      |> Enum.sort_by(& &1.sequence_number)

    case entries do
      [] ->
        {:error, :empty_range}

      [first | rest] ->
        # Verify first entry's hash
        if not Entry.verify_hash(first) do
          {:error, {:chain_broken, first.id}}
        else
          verify_chain_links([first | rest])
        end
    end
  end

  defp verify_chain_links([_single]), do: :ok

  defp verify_chain_links([prev, next | rest]) do
    cond do
      not Entry.verify_hash(next) ->
        {:error, {:chain_broken, next.id}}

      not Entry.verify_chain_link(prev, next) ->
        {:error, {:chain_broken, next.id}}

      true ->
        verify_chain_links([next | rest])
    end
  end

  defp get_timestamp_range(state) do
    case :ets.info(state.sequence_table, :size) do
      0 ->
        {nil, nil}

      _size ->
        # Get first (oldest) entry
        oldest =
          case :ets.first(state.sequence_table) do
            :"$end_of_table" ->
              nil

            first_seq ->
              [{^first_seq, id}] = :ets.lookup(state.sequence_table, first_seq)

              case :ets.lookup(state.entries_table, id) do
                [{^id, entry}] -> entry.timestamp
                [] -> nil
              end
          end

        # Get last (newest) entry
        newest =
          case :ets.last(state.sequence_table) do
            :"$end_of_table" ->
              nil

            last_seq ->
              [{^last_seq, id}] = :ets.lookup(state.sequence_table, last_seq)

              case :ets.lookup(state.entries_table, id) do
                [{^id, entry}] -> entry.timestamp
                [] -> nil
              end
          end

        {oldest, newest}
    end
  end
end
