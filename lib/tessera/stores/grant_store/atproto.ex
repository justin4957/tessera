defmodule Tessera.Stores.GrantStore.ATProto do
  @moduledoc """
  ATProto Personal Data Server (PDS) grant store adapter.

  Provides persistent grant storage using ATProto's repository system.
  Grants are stored as records in a custom Lexicon collection.

  ## Usage

      # Start the store
      {:ok, _pid} = Tessera.Stores.GrantStore.ATProto.start_link(
        identifier: "user.bsky.social",
        password: "app-password"
      )

      # Store a grant
      {:ok, grant} = Tessera.Stores.GrantStore.ATProto.store_grant(grant)

  ## Lexicon Collections

  The adapter uses the following collections:
  - `app.tessera.grant` - Grant records
  - `app.tessera.grant.index` - Index records for querying

  ## Configuration

      config :tessera, Tessera.Stores.GrantStore.ATProto,
        pds_url: "https://bsky.social",
        identifier: "your-handle.bsky.social",
        password: System.get_env("ATPROTO_APP_PASSWORD")
  """

  use GenServer

  @behaviour Tessera.Stores.GrantStore

  alias Tessera.Core.Grants.Grant
  alias Tessera.Stores.GrantStore.Serializer
  alias Tessera.Stores.ATProto.Client

  @grants_collection "app.tessera.grant"
  @index_collection "app.tessera.grant.index"

  defstruct [
    :session,
    :pds_url,
    :identifier,
    :password,
    :grants_collection,
    :index_collection
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the ATProto grant store.

  ## Options

  - `:name` - GenServer name (default: `__MODULE__`)
  - `:pds_url` - PDS URL (default: "https://bsky.social")
  - `:identifier` - Handle or DID for authentication
  - `:password` - App password for authentication
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
    state = %__MODULE__{
      pds_url: Keyword.get(opts, :pds_url, "https://bsky.social"),
      identifier: Keyword.get(opts, :identifier),
      password: Keyword.get(opts, :password),
      grants_collection: Keyword.get(opts, :grants_collection, @grants_collection),
      index_collection: Keyword.get(opts, :index_collection, @index_collection),
      session: nil
    }

    # Auto-connect if credentials provided
    if state.identifier && state.password do
      case do_connect(state) do
        {:ok, new_state} -> {:ok, new_state}
        {:error, reason} -> {:stop, reason}
      end
    else
      {:ok, state}
    end
  end

  @impl GenServer
  def handle_call({:store_grant, %Grant{} = grant}, _from, state) do
    with {:ok, state} <- ensure_session(state) do
      rkey = encode_rkey(grant.id)

      # Check if grant exists and is frozen
      case get_grant_record(state, rkey) do
        {:ok, existing} when existing.frozen == true ->
          {:reply, {:error, :frozen}, state}

        {:ok, existing} ->
          # Update: need to update indexes if resource/grantee changed
          update_indexes_if_changed(state, existing, grant)
          result = save_grant_record(state, grant)
          {:reply, result, state}

        {:error, :not_found} ->
          with {:ok, saved} <- save_grant_record(state, grant),
               :ok <- add_to_index(state, "resource", grant.resource_id, grant.id),
               :ok <- add_to_index(state, "grantee", grant.grantee_id, grant.id) do
            {:reply, {:ok, saved}, state}
          else
            error -> {:reply, error, state}
          end
      end
    else
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_call({:get_grant, grant_id}, _from, state) do
    with {:ok, state} <- ensure_session(state) do
      rkey = encode_rkey(grant_id)
      result = get_grant_record(state, rkey)
      {:reply, result, state}
    else
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_call({:delete_grant, grant_id}, _from, state) do
    with {:ok, state} <- ensure_session(state) do
      rkey = encode_rkey(grant_id)

      case get_grant_record(state, rkey) do
        {:ok, grant} ->
          if grant.frozen do
            {:reply, {:error, :frozen}, state}
          else
            # Remove from indexes
            remove_from_index(state, "resource", grant.resource_id, grant_id)
            remove_from_index(state, "grantee", grant.grantee_id, grant_id)

            # Delete the record
            opts = [pds_url: state.pds_url, collection: state.grants_collection]

            case Client.delete_record(state.session, rkey, opts) do
              :ok -> {:reply, :ok, state}
              error -> {:reply, error, state}
            end
          end

        {:error, :not_found} ->
          {:reply, {:error, :not_found}, state}

        error ->
          {:reply, error, state}
      end
    else
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_call({:list_grants_for_resource, resource_id, opts}, _from, state) do
    with {:ok, state} <- ensure_session(state) do
      result = list_grants_by_index(state, "resource", resource_id, opts)
      {:reply, result, state}
    else
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_call({:list_grants_for_grantee, grantee_id, opts}, _from, state) do
    with {:ok, state} <- ensure_session(state) do
      result = list_grants_by_index(state, "grantee", grantee_id, opts)
      {:reply, result, state}
    else
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_call({:list_grants, opts}, _from, state) do
    with {:ok, state} <- ensure_session(state) do
      collection_opts = [pds_url: state.pds_url, collection: state.grants_collection, limit: 100]

      case list_all_records(state.session, state.session.did, collection_opts, [], nil) do
        {:ok, records} ->
          grants =
            records
            |> Enum.map(fn record ->
              case Serializer.deserialize(record["value"]) do
                {:ok, grant} -> grant
                _ -> nil
              end
            end)
            |> Enum.reject(&is_nil/1)

          filtered = apply_filters(grants, opts)
          {:reply, {:ok, filtered}, state}

        error ->
          {:reply, error, state}
      end
    else
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_call({:revoke_grant, grant_id}, _from, state) do
    with {:ok, state} <- ensure_session(state) do
      rkey = encode_rkey(grant_id)

      case get_grant_record(state, rkey) do
        {:ok, grant} ->
          case Grant.revoke(grant) do
            {:ok, revoked} ->
              case save_grant_record(state, revoked) do
                {:ok, _} -> {:reply, {:ok, revoked}, state}
                error -> {:reply, error, state}
              end

            {:error, _} = error ->
              {:reply, error, state}
          end

        error ->
          {:reply, error, state}
      end
    else
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_call({:freeze_grant, grant_id}, _from, state) do
    with {:ok, state} <- ensure_session(state) do
      rkey = encode_rkey(grant_id)

      case get_grant_record(state, rkey) do
        {:ok, grant} ->
          case Grant.freeze(grant) do
            {:ok, frozen} ->
              case save_grant_record(state, frozen) do
                {:ok, _} -> {:reply, {:ok, frozen}, state}
                error -> {:reply, error, state}
              end

            {:error, _} = error ->
              {:reply, error, state}
          end

        error ->
          {:reply, error, state}
      end
    else
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_call(:info, _from, state) do
    info = %{
      type: :atproto,
      pds_url: state.pds_url,
      did: state.session && state.session.did,
      handle: state.session && state.session.handle,
      connected: state.session != nil,
      grants_collection: state.grants_collection,
      index_collection: state.index_collection,
      persistent: true,
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

  defp do_connect(%{identifier: nil}), do: {:error, :missing_identifier}
  defp do_connect(%{password: nil}), do: {:error, :missing_password}

  defp do_connect(state) do
    case Client.create_session(state.identifier, state.password, pds_url: state.pds_url) do
      {:ok, session} -> {:ok, %{state | session: session}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp ensure_session(%{session: nil} = state), do: do_connect(state)
  defp ensure_session(state), do: {:ok, state}

  defp encode_rkey(grant_id) do
    grant_id
    |> Base.url_encode64(padding: false)
    |> String.replace(~r/[^a-zA-Z0-9._:~-]/, "_")
  end

  defp get_grant_record(state, rkey) do
    opts = [pds_url: state.pds_url, collection: state.grants_collection]

    case Client.get_record(state.session, state.session.did, rkey, opts) do
      {:ok, %{"value" => record}} ->
        Serializer.deserialize(record)

      {:error, :not_found} ->
        {:error, :not_found}

      error ->
        error
    end
  end

  defp save_grant_record(state, grant) do
    rkey = encode_rkey(grant.id)

    with {:ok, serialized} <- Serializer.serialize(grant) do
      opts = [pds_url: state.pds_url, collection: state.grants_collection]

      case Client.put_record(state.session, rkey, serialized, opts) do
        {:ok, _} -> {:ok, grant}
        error -> error
      end
    end
  end

  defp index_rkey(index_type, key) do
    hashed = :crypto.hash(:sha256, "#{index_type}:#{key}")

    Base.url_encode64(hashed, padding: false)
    |> String.slice(0, 32)
  end

  defp add_to_index(state, index_type, key, grant_id) do
    rkey = index_rkey(index_type, key)
    opts = [pds_url: state.pds_url, collection: state.index_collection]

    # Get existing index or create new
    grant_ids =
      case Client.get_record(state.session, state.session.did, rkey, opts) do
        {:ok, %{"value" => %{"grant_ids" => ids}}} -> ids
        _ -> []
      end

    # Add grant_id if not present
    updated_ids =
      if grant_id in grant_ids do
        grant_ids
      else
        [grant_id | grant_ids]
      end

    record = %{
      "index_type" => index_type,
      "key" => key,
      "grant_ids" => updated_ids
    }

    case Client.put_record(state.session, rkey, record, opts) do
      {:ok, _} -> :ok
      error -> error
    end
  end

  defp remove_from_index(state, index_type, key, grant_id) do
    rkey = index_rkey(index_type, key)
    opts = [pds_url: state.pds_url, collection: state.index_collection]

    case Client.get_record(state.session, state.session.did, rkey, opts) do
      {:ok, %{"value" => %{"grant_ids" => ids} = value}} ->
        updated_ids = Enum.reject(ids, &(&1 == grant_id))

        if Enum.empty?(updated_ids) do
          Client.delete_record(state.session, rkey, opts)
        else
          updated_record = %{value | "grant_ids" => updated_ids}
          Client.put_record(state.session, rkey, updated_record, opts)
        end

        :ok

      _ ->
        :ok
    end
  end

  defp update_indexes_if_changed(state, existing, new_grant) do
    if existing.resource_id != new_grant.resource_id do
      remove_from_index(state, "resource", existing.resource_id, existing.id)
      add_to_index(state, "resource", new_grant.resource_id, new_grant.id)
    end

    if existing.grantee_id != new_grant.grantee_id do
      remove_from_index(state, "grantee", existing.grantee_id, existing.id)
      add_to_index(state, "grantee", new_grant.grantee_id, new_grant.id)
    end
  end

  defp list_grants_by_index(state, index_type, key, opts) do
    rkey = index_rkey(index_type, key)
    index_opts = [pds_url: state.pds_url, collection: state.index_collection]

    case Client.get_record(state.session, state.session.did, rkey, index_opts) do
      {:ok, %{"value" => %{"grant_ids" => grant_ids}}} ->
        grants =
          grant_ids
          |> Enum.map(fn id ->
            grant_rkey = encode_rkey(id)

            case get_grant_record(state, grant_rkey) do
              {:ok, grant} -> grant
              _ -> nil
            end
          end)
          |> Enum.reject(&is_nil/1)

        {:ok, apply_filters(grants, opts)}

      {:error, :not_found} ->
        {:ok, []}

      error ->
        error
    end
  end

  defp list_all_records(session, did, opts, acc, cursor) do
    list_opts = if cursor, do: Keyword.put(opts, :cursor, cursor), else: opts

    case Client.list_records(session, did, list_opts) do
      {:ok, %{"records" => records, "cursor" => next_cursor}} when is_binary(next_cursor) ->
        list_all_records(session, did, opts, acc ++ records, next_cursor)

      {:ok, %{"records" => records}} ->
        {:ok, acc ++ records}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp apply_filters(grants, opts) do
    grants
    |> filter_active_only(Keyword.get(opts, :active_only, false))
    |> filter_include_revoked(Keyword.get(opts, :include_revoked, true))
    |> filter_at_time(Keyword.get(opts, :at))
    |> maybe_offset(Keyword.get(opts, :offset))
    |> maybe_limit(Keyword.get(opts, :limit))
  end

  defp filter_active_only(grants, false), do: grants
  defp filter_active_only(grants, true), do: Enum.filter(grants, &Grant.active?/1)

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
