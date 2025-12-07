defmodule Tessera.Stores.GrantStore.Solid do
  @moduledoc """
  Solid Pod grant store adapter.

  Provides persistent grant storage using Solid Pods. Grants are stored
  as JSON documents with secondary index files for efficient querying.

  ## Usage

      # Start the store
      {:ok, _pid} = Tessera.Stores.GrantStore.Solid.start_link(
        pod_url: "https://pod.example.com/user/",
        credentials: %{id: "client-id", secret: "client-secret"}
      )

      # Store a grant
      {:ok, grant} = Tessera.Stores.GrantStore.Solid.store_grant(grant)

  ## Storage Structure

  Grants are stored in the Pod with the following structure:

      tessera/
      └── grants/
          ├── {grant_id}.json           # Grant data
          ├── index/
          │   ├── by_resource/
          │   │   └── {resource_hash}.json  # List of grant IDs
          │   └── by_grantee/
          │       └── {grantee_hash}.json   # List of grant IDs

  ## Configuration

      config :tessera, Tessera.Stores.GrantStore.Solid,
        pod_url: "https://pod.example.com/user/",
        credentials: %{
          id: System.get_env("SOLID_CLIENT_ID"),
          secret: System.get_env("SOLID_CLIENT_SECRET")
        },
        base_path: "tessera/grants/"
  """

  use GenServer

  @behaviour Tessera.Stores.GrantStore

  alias Tessera.Core.Grants.Grant
  alias Tessera.Stores.GrantStore.Serializer
  alias Tessera.Stores.Solid.Client

  @default_base_path "tessera/grants/"

  defstruct [
    :session,
    :pod_url,
    :credentials,
    :base_path,
    :token_endpoint
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the Solid grant store.

  ## Options

  - `:name` - GenServer name (default: `__MODULE__`)
  - `:pod_url` - Base URL of the Solid Pod (required)
  - `:credentials` - Map with `:id` and `:secret` for authentication
  - `:base_path` - Base path for grants (default: "tessera/grants/")
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
      pod_url: Keyword.get(opts, :pod_url),
      credentials: Keyword.get(opts, :credentials),
      base_path: Keyword.get(opts, :base_path, @default_base_path),
      token_endpoint: Keyword.get(opts, :token_endpoint),
      session: nil
    }

    # Auto-connect if credentials provided
    if state.pod_url && state.credentials do
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
      # Check if grant exists and is frozen
      grant_path = grant_path(state.base_path, grant.id)

      existing_result = get_grant_from_pod(state.session, grant_path)

      case existing_result do
        {:ok, existing} when existing.frozen == true ->
          {:reply, {:error, :frozen}, state}

        {:ok, existing} ->
          # Update: remove from old indexes if resource/grantee changed
          if existing.resource_id != grant.resource_id do
            remove_from_index(state, "by_resource", existing.resource_id, grant.id)
          end

          if existing.grantee_id != grant.grantee_id do
            remove_from_index(state, "by_grantee", existing.grantee_id, grant.id)
          end

          store_grant_to_pod(grant, state)

        {:error, :not_found} ->
          store_grant_to_pod(grant, state)
      end
    else
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_call({:get_grant, grant_id}, _from, state) do
    with {:ok, state} <- ensure_session(state) do
      grant_path = grant_path(state.base_path, grant_id)
      result = get_grant_from_pod(state.session, grant_path)
      {:reply, result, state}
    else
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_call({:delete_grant, grant_id}, _from, state) do
    with {:ok, state} <- ensure_session(state) do
      grant_path = grant_path(state.base_path, grant_id)

      case get_grant_from_pod(state.session, grant_path) do
        {:ok, grant} ->
          if grant.frozen do
            {:reply, {:error, :frozen}, state}
          else
            # Remove from indexes
            remove_from_index(state, "by_resource", grant.resource_id, grant_id)
            remove_from_index(state, "by_grantee", grant.grantee_id, grant_id)

            # Delete the grant
            case Client.delete_resource(state.session, grant_path) do
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
      result = list_grants_by_index(state, "by_resource", resource_id, opts)
      {:reply, result, state}
    else
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_call({:list_grants_for_grantee, grantee_id, opts}, _from, state) do
    with {:ok, state} <- ensure_session(state) do
      result = list_grants_by_index(state, "by_grantee", grantee_id, opts)
      {:reply, result, state}
    else
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_call({:list_grants, opts}, _from, state) do
    with {:ok, state} <- ensure_session(state) do
      grants_container = String.trim_trailing(state.base_path, "/") <> "/"

      case list_all_grants(state.session, grants_container) do
        {:ok, grants} ->
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
      grant_path = grant_path(state.base_path, grant_id)

      case get_grant_from_pod(state.session, grant_path) do
        {:ok, grant} ->
          case Grant.revoke(grant) do
            {:ok, revoked} ->
              case save_grant_to_pod(revoked, state) do
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
      grant_path = grant_path(state.base_path, grant_id)

      case get_grant_from_pod(state.session, grant_path) do
        {:ok, grant} ->
          case Grant.freeze(grant) do
            {:ok, frozen} ->
              case save_grant_to_pod(frozen, state) do
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
      type: :solid,
      pod_url: state.pod_url,
      base_path: state.base_path,
      webid: state.session && state.session.webid,
      connected: state.session != nil,
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

  defp do_connect(%{pod_url: nil}), do: {:error, :missing_pod_url}
  defp do_connect(%{credentials: nil}), do: {:error, :missing_credentials}

  defp do_connect(state) do
    opts = if state.token_endpoint, do: [token_endpoint: state.token_endpoint], else: []

    case Client.create_session(state.pod_url, state.credentials, opts) do
      {:ok, session} -> {:ok, %{state | session: session}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp ensure_session(%{session: nil} = state), do: do_connect(state)

  defp ensure_session(state) do
    if state.session.expires_at &&
         DateTime.compare(DateTime.utc_now(), state.session.expires_at) == :gt do
      do_connect(state)
    else
      {:ok, state}
    end
  end

  defp grant_path(base_path, grant_id) do
    safe_id = sanitize_id(grant_id)
    base = String.trim_trailing(base_path, "/")
    "#{base}/#{safe_id}.json"
  end

  defp index_path(base_path, index_type, key) do
    hashed_key = hash_key(key)
    base = String.trim_trailing(base_path, "/")
    "#{base}/index/#{index_type}/#{hashed_key}.json"
  end

  defp sanitize_id(id) do
    id
    |> String.replace(~r/[^a-zA-Z0-9_-]/, "_")
  end

  defp hash_key(key) do
    :crypto.hash(:sha256, key)
    |> Base.url_encode64(padding: false)
    |> String.slice(0, 32)
  end

  defp store_grant_to_pod(grant, state) do
    with {:ok, _} <- save_grant_to_pod(grant, state),
         :ok <- add_to_index(state, "by_resource", grant.resource_id, grant.id),
         :ok <- add_to_index(state, "by_grantee", grant.grantee_id, grant.id) do
      {:reply, {:ok, grant}, state}
    else
      error -> {:reply, error, state}
    end
  end

  defp save_grant_to_pod(grant, state) do
    grant_path = grant_path(state.base_path, grant.id)

    with {:ok, serialized} <- Serializer.serialize(grant),
         content = Jason.encode!(serialized),
         :ok <- ensure_containers(state.session, grant_path),
         {:ok, _} <-
           Client.put_resource(state.session, grant_path, content,
             content_type: "application/json"
           ) do
      {:ok, grant}
    end
  end

  defp get_grant_from_pod(session, grant_path) do
    case Client.get_resource(session, grant_path, accept: "application/json") do
      {:ok, body, _metadata} ->
        data = if is_binary(body), do: Jason.decode!(body), else: body
        Serializer.deserialize(data)

      {:error, :not_found} ->
        {:error, :not_found}

      error ->
        error
    end
  end

  defp add_to_index(state, index_type, key, grant_id) do
    path = index_path(state.base_path, index_type, key)

    # Get existing index or create new
    grant_ids =
      case Client.get_resource(state.session, path, accept: "application/json") do
        {:ok, body, _} ->
          data = if is_binary(body), do: Jason.decode!(body), else: body
          Map.get(data, "grant_ids", [])

        {:error, :not_found} ->
          []

        _ ->
          []
      end

    # Add grant_id if not present
    updated_ids =
      if grant_id in grant_ids do
        grant_ids
      else
        [grant_id | grant_ids]
      end

    # Save index
    content = Jason.encode!(%{"key" => key, "grant_ids" => updated_ids})

    with :ok <- ensure_containers(state.session, path),
         {:ok, _} <-
           Client.put_resource(state.session, path, content, content_type: "application/json") do
      :ok
    end
  end

  defp remove_from_index(state, index_type, key, grant_id) do
    path = index_path(state.base_path, index_type, key)

    case Client.get_resource(state.session, path, accept: "application/json") do
      {:ok, body, _} ->
        data = if is_binary(body), do: Jason.decode!(body), else: body
        grant_ids = Map.get(data, "grant_ids", [])
        updated_ids = Enum.reject(grant_ids, &(&1 == grant_id))

        if Enum.empty?(updated_ids) do
          Client.delete_resource(state.session, path)
        else
          content = Jason.encode!(%{"key" => key, "grant_ids" => updated_ids})
          Client.put_resource(state.session, path, content, content_type: "application/json")
        end

        :ok

      _ ->
        :ok
    end
  end

  defp list_grants_by_index(state, index_type, key, opts) do
    path = index_path(state.base_path, index_type, key)

    case Client.get_resource(state.session, path, accept: "application/json") do
      {:ok, body, _} ->
        data = if is_binary(body), do: Jason.decode!(body), else: body
        grant_ids = Map.get(data, "grant_ids", [])

        grants =
          grant_ids
          |> Enum.map(fn id ->
            grant_path = grant_path(state.base_path, id)

            case get_grant_from_pod(state.session, grant_path) do
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

  defp list_all_grants(session, grants_container) do
    case Client.list_container(session, grants_container) do
      {:ok, resources} ->
        grants =
          resources
          |> Enum.filter(&String.ends_with?(&1, ".json"))
          |> Enum.reject(&String.contains?(&1, "/index/"))
          |> Enum.map(fn path ->
            case get_grant_from_pod(session, path) do
              {:ok, grant} -> grant
              _ -> nil
            end
          end)
          |> Enum.reject(&is_nil/1)

        {:ok, grants}

      {:error, :not_found} ->
        {:ok, []}

      error ->
        error
    end
  end

  defp ensure_containers(session, resource_path) do
    path_parts = String.split(resource_path, "/")
    container_parts = Enum.drop(path_parts, -1)

    ensure_container_chain(session, container_parts, "")
  end

  defp ensure_container_chain(_session, [], _current), do: :ok

  defp ensure_container_chain(session, [part | rest], current) do
    container_path = if current == "", do: part, else: "#{current}/#{part}"

    case Client.create_container(session, container_path) do
      {:ok, _} ->
        ensure_container_chain(session, rest, container_path)

      {:error, {:create_container_failed, status, _}} when status in [409, 405] ->
        ensure_container_chain(session, rest, container_path)

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
