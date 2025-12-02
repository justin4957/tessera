defmodule Tessera.Stores.Memory.Adapter do
  @moduledoc """
  In-memory storage adapter for testing and development.

  Data is stored in an ETS table and does not persist across restarts.
  Useful for unit testing and local development without external dependencies.

  ## Usage

      {:ok, _pid} = Tessera.Stores.Memory.Adapter.start_link(name: :my_store)

      :ok = Tessera.Stores.Memory.Adapter.put("resource/1", %{data: "value"}, %{})
      {:ok, data, meta} = Tessera.Stores.Memory.Adapter.get("resource/1")
  """

  use GenServer
  @behaviour Tessera.Store

  defstruct [:table_name]

  # Client API

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @impl Tessera.Store
  def put(resource_id, data, metadata, server \\ __MODULE__) do
    GenServer.call(server, {:put, resource_id, data, metadata})
  end

  @impl Tessera.Store
  def get(resource_id, server \\ __MODULE__) do
    GenServer.call(server, {:get, resource_id})
  end

  @impl Tessera.Store
  def delete(resource_id, server \\ __MODULE__) do
    GenServer.call(server, {:delete, resource_id})
  end

  @impl Tessera.Store
  def list(prefix \\ nil, server \\ __MODULE__) do
    GenServer.call(server, {:list, prefix})
  end

  @impl Tessera.Store
  def exists?(resource_id, server \\ __MODULE__) do
    GenServer.call(server, {:exists?, resource_id})
  end

  @impl Tessera.Store
  def info(server \\ __MODULE__) do
    GenServer.call(server, :info)
  end

  # Server Callbacks

  @impl GenServer
  def init(opts) do
    table_name = Keyword.get(opts, :table_name, :tessera_memory_store)
    table = :ets.new(table_name, [:set, :protected, :named_table])
    {:ok, %__MODULE__{table_name: table}}
  end

  @impl GenServer
  def handle_call({:put, resource_id, data, metadata}, _from, state) do
    timestamp = DateTime.utc_now()

    enriched_metadata =
      Map.merge(metadata, %{
        created_at: Map.get(metadata, :created_at, timestamp),
        updated_at: timestamp
      })

    :ets.insert(state.table_name, {resource_id, data, enriched_metadata})
    {:reply, :ok, state}
  end

  @impl GenServer
  def handle_call({:get, resource_id}, _from, state) do
    result =
      case :ets.lookup(state.table_name, resource_id) do
        [{^resource_id, data, metadata}] -> {:ok, data, metadata}
        [] -> {:error, :not_found}
      end

    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:delete, resource_id}, _from, state) do
    result =
      case :ets.lookup(state.table_name, resource_id) do
        [{^resource_id, _data, _metadata}] ->
          :ets.delete(state.table_name, resource_id)
          :ok

        [] ->
          {:error, :not_found}
      end

    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:list, nil}, _from, state) do
    resource_ids =
      :ets.foldl(
        fn {resource_id, _data, _meta}, acc ->
          [resource_id | acc]
        end,
        [],
        state.table_name
      )

    {:reply, {:ok, Enum.sort(resource_ids)}, state}
  end

  @impl GenServer
  def handle_call({:list, prefix}, _from, state) do
    resource_ids =
      :ets.foldl(
        fn {resource_id, _data, _meta}, acc ->
          if String.starts_with?(resource_id, prefix) do
            [resource_id | acc]
          else
            acc
          end
        end,
        [],
        state.table_name
      )

    {:reply, {:ok, Enum.sort(resource_ids)}, state}
  end

  @impl GenServer
  def handle_call({:exists?, resource_id}, _from, state) do
    result = :ets.member(state.table_name, resource_id)
    {:reply, result, state}
  end

  @impl GenServer
  def handle_call(:info, _from, state) do
    count = :ets.info(state.table_name, :size)

    info = %{
      type: :memory,
      table_name: state.table_name,
      resource_count: count,
      capabilities: [:read, :write, :delete, :list],
      persistent: false
    }

    {:reply, info, state}
  end
end
