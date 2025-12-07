defmodule Tessera.Stores.GrantStore.Memory do
  @moduledoc """
  In-memory grant store adapter using ETS.

  Provides fast, in-memory storage for grants with indexing support.
  Data does not persist across process restarts.

  ## Usage

      # Start the store
      {:ok, _pid} = Tessera.Stores.GrantStore.Memory.start_link()

      # Store a grant
      {:ok, grant} = Tessera.Stores.GrantStore.Memory.store_grant(grant)

      # Query grants
      {:ok, grants} = Tessera.Stores.GrantStore.Memory.list_grants_for_resource("pod://data")

  ## Indexes

  The adapter maintains secondary indexes for:
  - Resource ID -> [Grant ID]
  - Grantee ID -> [Grant ID]

  This enables O(1) lookups by resource or grantee.
  """

  use GenServer

  @behaviour Tessera.Stores.GrantStore

  alias Tessera.Core.Grants.Grant

  @grants_table :tessera_grants
  @resource_index :tessera_grants_by_resource
  @grantee_index :tessera_grants_by_grantee

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the memory grant store.

  ## Options

  - `:name` - GenServer name (default: `__MODULE__`)
  """
  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Stops the grant store.
  """
  def stop(server \\ __MODULE__) do
    GenServer.stop(server)
  end

  @doc """
  Clears all stored grants and indexes.
  """
  def clear(server \\ __MODULE__) do
    GenServer.call(server, :clear)
  end

  # ============================================================================
  # GrantStore Behaviour Implementation
  # ============================================================================

  @impl Tessera.Stores.GrantStore
  def store_grant(grant, server \\ __MODULE__) do
    GenServer.call(server, {:store_grant, grant})
  end

  @impl Tessera.Stores.GrantStore
  def get_grant(grant_id, server \\ __MODULE__) do
    GenServer.call(server, {:get_grant, grant_id})
  end

  @impl Tessera.Stores.GrantStore
  def delete_grant(grant_id, server \\ __MODULE__) do
    GenServer.call(server, {:delete_grant, grant_id})
  end

  @impl Tessera.Stores.GrantStore
  def list_grants_for_resource(resource_id, opts \\ [], server \\ __MODULE__) do
    GenServer.call(server, {:list_grants_for_resource, resource_id, opts})
  end

  @impl Tessera.Stores.GrantStore
  def list_grants_for_grantee(grantee_id, opts \\ [], server \\ __MODULE__) do
    GenServer.call(server, {:list_grants_for_grantee, grantee_id, opts})
  end

  @impl Tessera.Stores.GrantStore
  def list_grants(opts \\ [], server \\ __MODULE__) do
    GenServer.call(server, {:list_grants, opts})
  end

  @impl Tessera.Stores.GrantStore
  def revoke_grant(grant_id, server \\ __MODULE__) do
    GenServer.call(server, {:revoke_grant, grant_id})
  end

  @impl Tessera.Stores.GrantStore
  def freeze_grant(grant_id, server \\ __MODULE__) do
    GenServer.call(server, {:freeze_grant, grant_id})
  end

  @impl Tessera.Stores.GrantStore
  def info(server \\ __MODULE__) do
    GenServer.call(server, :info)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl GenServer
  def init(opts) do
    table_prefix = Keyword.get(opts, :table_prefix, "")

    grants_table = table_name(@grants_table, table_prefix)
    resource_index = table_name(@resource_index, table_prefix)
    grantee_index = table_name(@grantee_index, table_prefix)

    # Create ETS tables
    :ets.new(grants_table, [:set, :named_table, :protected])
    :ets.new(resource_index, [:bag, :named_table, :protected])
    :ets.new(grantee_index, [:bag, :named_table, :protected])

    state = %{
      grants_table: grants_table,
      resource_index: resource_index,
      grantee_index: grantee_index
    }

    {:ok, state}
  end

  @impl GenServer
  def handle_call(:clear, _from, state) do
    :ets.delete_all_objects(state.grants_table)
    :ets.delete_all_objects(state.resource_index)
    :ets.delete_all_objects(state.grantee_index)
    {:reply, :ok, state}
  end

  @impl GenServer
  def handle_call({:store_grant, %Grant{} = grant}, _from, state) do
    # Check if grant exists and is frozen
    case :ets.lookup(state.grants_table, grant.id) do
      [{_, existing}] when existing.frozen == true ->
        {:reply, {:error, :frozen}, state}

      [{_, existing}] ->
        # Update existing grant - remove old indexes first
        remove_from_indexes(existing, state)
        do_store_grant(grant, state)
        {:reply, {:ok, grant}, state}

      [] ->
        do_store_grant(grant, state)
        {:reply, {:ok, grant}, state}
    end
  end

  @impl GenServer
  def handle_call({:get_grant, grant_id}, _from, state) do
    result =
      case :ets.lookup(state.grants_table, grant_id) do
        [{^grant_id, grant}] -> {:ok, grant}
        [] -> {:error, :not_found}
      end

    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:delete_grant, grant_id}, _from, state) do
    result =
      case :ets.lookup(state.grants_table, grant_id) do
        [{^grant_id, grant}] ->
          if grant.frozen do
            {:error, :frozen}
          else
            remove_from_indexes(grant, state)
            :ets.delete(state.grants_table, grant_id)
            :ok
          end

        [] ->
          {:error, :not_found}
      end

    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:list_grants_for_resource, resource_id, opts}, _from, state) do
    grant_ids =
      :ets.lookup(state.resource_index, resource_id)
      |> Enum.map(fn {_, grant_id} -> grant_id end)

    grants = fetch_and_filter_grants(grant_ids, opts, state)
    {:reply, {:ok, grants}, state}
  end

  @impl GenServer
  def handle_call({:list_grants_for_grantee, grantee_id, opts}, _from, state) do
    grant_ids =
      :ets.lookup(state.grantee_index, grantee_id)
      |> Enum.map(fn {_, grant_id} -> grant_id end)

    grants = fetch_and_filter_grants(grant_ids, opts, state)
    {:reply, {:ok, grants}, state}
  end

  @impl GenServer
  def handle_call({:list_grants, opts}, _from, state) do
    grants =
      :ets.foldl(
        fn {_id, grant}, acc -> [grant | acc] end,
        [],
        state.grants_table
      )

    filtered = apply_filters(grants, opts)

    # Apply pagination
    limited =
      filtered
      |> maybe_offset(Keyword.get(opts, :offset))
      |> maybe_limit(Keyword.get(opts, :limit))

    {:reply, {:ok, limited}, state}
  end

  @impl GenServer
  def handle_call({:revoke_grant, grant_id}, _from, state) do
    result =
      case :ets.lookup(state.grants_table, grant_id) do
        [{^grant_id, grant}] ->
          case Grant.revoke(grant) do
            {:ok, revoked} ->
              :ets.insert(state.grants_table, {grant_id, revoked})
              {:ok, revoked}

            {:error, _} = error ->
              error
          end

        [] ->
          {:error, :not_found}
      end

    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:freeze_grant, grant_id}, _from, state) do
    result =
      case :ets.lookup(state.grants_table, grant_id) do
        [{^grant_id, grant}] ->
          case Grant.freeze(grant) do
            {:ok, frozen} ->
              :ets.insert(state.grants_table, {grant_id, frozen})
              {:ok, frozen}

            {:error, _} = error ->
              error
          end

        [] ->
          {:error, :not_found}
      end

    {:reply, result, state}
  end

  @impl GenServer
  def handle_call(:info, _from, state) do
    count = :ets.info(state.grants_table, :size)

    info = %{
      type: :memory,
      grant_count: count,
      persistent: false,
      capabilities: [
        :store,
        :get,
        :delete,
        :list,
        :query_by_resource,
        :query_by_grantee,
        :revoke,
        :freeze
      ],
      indexes: [:resource_id, :grantee_id]
    }

    {:reply, info, state}
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp table_name(base, ""), do: base
  defp table_name(base, prefix), do: :"#{prefix}_#{base}"

  defp do_store_grant(grant, state) do
    # Store the grant
    :ets.insert(state.grants_table, {grant.id, grant})

    # Update indexes
    :ets.insert(state.resource_index, {grant.resource_id, grant.id})
    :ets.insert(state.grantee_index, {grant.grantee_id, grant.id})
  end

  defp remove_from_indexes(grant, state) do
    :ets.delete_object(state.resource_index, {grant.resource_id, grant.id})
    :ets.delete_object(state.grantee_index, {grant.grantee_id, grant.id})
  end

  defp fetch_and_filter_grants(grant_ids, opts, state) do
    grants =
      Enum.reduce(grant_ids, [], fn grant_id, acc ->
        case :ets.lookup(state.grants_table, grant_id) do
          [{^grant_id, grant}] -> [grant | acc]
          [] -> acc
        end
      end)

    apply_filters(grants, opts)
  end

  defp apply_filters(grants, opts) do
    grants
    |> filter_active_only(Keyword.get(opts, :active_only, false))
    |> filter_include_revoked(Keyword.get(opts, :include_revoked, true))
    |> filter_at_time(Keyword.get(opts, :at))
  end

  defp filter_active_only(grants, false), do: grants

  defp filter_active_only(grants, true) do
    Enum.filter(grants, &Grant.active?/1)
  end

  defp filter_include_revoked(grants, true), do: grants

  defp filter_include_revoked(grants, false) do
    Enum.filter(grants, fn grant -> is_nil(grant.revoked_at) end)
  end

  defp filter_at_time(grants, nil), do: grants

  defp filter_at_time(grants, %DateTime{} = at) do
    Enum.filter(grants, fn grant -> Grant.active_at?(grant, at) end)
  end

  defp maybe_offset(grants, nil), do: grants
  defp maybe_offset(grants, offset), do: Enum.drop(grants, offset)

  defp maybe_limit(grants, nil), do: grants
  defp maybe_limit(grants, limit), do: Enum.take(grants, limit)
end
