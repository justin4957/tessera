defmodule Tessera.Stores.Solid.Adapter do
  @moduledoc """
  Solid Pod storage adapter for Tessera.

  Implements the `Tessera.Store` behaviour using the Solid Protocol
  for data storage. This enables Tessera to use W3C standard personal
  data stores as a storage backend.

  ## Configuration

  Configure the adapter in your config:

      config :tessera, Tessera.Stores.Solid.Adapter,
        pod_url: "https://pod.inrupt.com/username/",
        credentials: %{
          id: System.get_env("SOLID_CLIENT_ID"),
          secret: System.get_env("SOLID_CLIENT_SECRET")
        }

  ## Usage

      # Start the adapter with client credentials
      {:ok, pid} = Tessera.Stores.Solid.Adapter.start_link(
        name: :my_solid_store,
        pod_url: "https://pod.example.com/alice/",
        credentials: %{id: "client-id", secret: "client-secret"}
      )

      # Or connect later
      {:ok, pid} = Tessera.Stores.Solid.Adapter.start_link(
        name: :my_solid_store,
        pod_url: "https://pod.example.com/alice/"
      )
      :ok = Tessera.Stores.Solid.Adapter.connect(
        [credentials: %{id: "id", secret: "secret"}],
        :my_solid_store
      )

      # Store data
      :ok = Tessera.Stores.Solid.Adapter.put(
        "tessera/records/my-resource",
        %{name: "test", value: 123},
        %{},
        :my_solid_store
      )

  ## Resource Path Mapping

  Resource IDs are mapped to Pod paths under a configurable base path
  (default: "tessera/"). The adapter stores data as JSON files.

  ## Solid Protocol Compliance

  This adapter implements:
  - LDP resource CRUD operations (GET, PUT, DELETE)
  - Container management for hierarchical data
  - Content negotiation (defaults to JSON)
  - ETag support for optimistic concurrency
  """

  use GenServer
  @behaviour Tessera.Store

  alias Tessera.Stores.Solid.Client

  @default_base_path "tessera/"

  defstruct [
    :session,
    :pod_url,
    :credentials,
    :base_path,
    :token_endpoint
  ]

  # Client API

  @doc """
  Starts the Solid adapter as a GenServer.

  ## Options

  - `:name` - GenServer name (default: `__MODULE__`)
  - `:pod_url` - Base URL of the Solid Pod (required)
  - `:credentials` - Map with `:id` and `:secret` for authentication
  - `:base_path` - Base path for Tessera data (default: "tessera/")
  - `:token_endpoint` - OAuth token endpoint (auto-discovered if not set)
  """
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

  @impl Tessera.Store
  def connect(opts, server \\ __MODULE__) do
    GenServer.call(server, {:connect, opts})
  end

  @impl Tessera.Store
  def disconnect(server \\ __MODULE__) do
    GenServer.call(server, :disconnect)
  end

  # Server Callbacks

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
  def handle_call({:put, resource_id, data, metadata}, _from, state) do
    with {:ok, state} <- ensure_session(state) do
      resource_path = build_resource_path(state.base_path, resource_id)
      timestamp = DateTime.utc_now() |> DateTime.to_iso8601()

      record = %{
        "resourceId" => resource_id,
        "data" => data,
        "metadata" => metadata,
        "createdAt" => Map.get(metadata, :created_at, timestamp) |> to_iso8601(),
        "updatedAt" => timestamp
      }

      content = Jason.encode!(record)

      # Ensure parent containers exist
      case ensure_containers(state.session, resource_path) do
        :ok ->
          case Client.put_resource(state.session, resource_path, content,
                 content_type: "application/json"
               ) do
            {:ok, _metadata} ->
              {:reply, :ok, state}

            {:error, reason} ->
              {:reply, {:error, reason}, state}
          end

        {:error, reason} ->
          {:reply, {:error, reason}, state}
      end
    else
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_call({:get, resource_id}, _from, state) do
    with {:ok, state} <- ensure_session(state) do
      resource_path = build_resource_path(state.base_path, resource_id)

      case Client.get_resource(state.session, resource_path, accept: "application/json") do
        {:ok, body, solid_metadata} ->
          record = if is_binary(body), do: Jason.decode!(body), else: body
          data = record["data"]

          metadata = %{
            created_at: parse_datetime(record["createdAt"]),
            updated_at: parse_datetime(record["updatedAt"]),
            etag: solid_metadata.etag,
            solid: Map.get(record, "metadata", %{})
          }

          {:reply, {:ok, data, metadata}, state}

        {:error, :not_found} ->
          {:reply, {:error, :not_found}, state}

        {:error, reason} ->
          {:reply, {:error, reason}, state}
      end
    else
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_call({:delete, resource_id}, _from, state) do
    with {:ok, state} <- ensure_session(state) do
      resource_path = build_resource_path(state.base_path, resource_id)

      case Client.delete_resource(state.session, resource_path) do
        :ok ->
          {:reply, :ok, state}

        {:error, :not_found} ->
          {:reply, {:error, :not_found}, state}

        {:error, reason} ->
          {:reply, {:error, reason}, state}
      end
    else
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_call({:list, prefix}, _from, state) do
    with {:ok, state} <- ensure_session(state) do
      base_container = state.base_path

      case list_resources_recursive(state.session, base_container, []) do
        {:ok, all_paths} ->
          resource_ids =
            all_paths
            |> Enum.map(&extract_resource_id(&1, state.base_path))
            |> Enum.reject(&is_nil/1)
            |> Enum.filter(fn id ->
              prefix == nil || String.starts_with?(id, prefix)
            end)
            |> Enum.sort()

          {:reply, {:ok, resource_ids}, state}

        {:error, reason} ->
          {:reply, {:error, reason}, state}
      end
    else
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_call({:exists?, resource_id}, _from, state) do
    with {:ok, state} <- ensure_session(state) do
      resource_path = build_resource_path(state.base_path, resource_id)

      result =
        case Client.head_resource(state.session, resource_path) do
          {:ok, _metadata} -> true
          {:error, :not_found} -> false
          {:error, _} -> false
        end

      {:reply, result, state}
    else
      {:error, _reason} ->
        {:reply, false, state}
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
      capabilities: [:read, :write, :delete, :list],
      persistent: true
    }

    {:reply, info, state}
  end

  @impl GenServer
  def handle_call({:connect, opts}, _from, state) do
    new_state = %{
      state
      | credentials: Keyword.get(opts, :credentials, state.credentials),
        pod_url: Keyword.get(opts, :pod_url, state.pod_url),
        token_endpoint: Keyword.get(opts, :token_endpoint, state.token_endpoint)
    }

    case do_connect(new_state) do
      {:ok, connected_state} -> {:reply, :ok, connected_state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_call(:disconnect, _from, state) do
    {:reply, :ok, %{state | session: nil}}
  end

  # Private helpers

  defp do_connect(%{pod_url: nil}), do: {:error, :missing_pod_url}
  defp do_connect(%{credentials: nil}), do: {:error, :missing_credentials}

  defp do_connect(state) do
    opts = if state.token_endpoint, do: [token_endpoint: state.token_endpoint], else: []

    case Client.create_session(state.pod_url, state.credentials, opts) do
      {:ok, session} ->
        {:ok, %{state | session: session}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp ensure_session(%{session: nil} = state) do
    do_connect(state)
  end

  defp ensure_session(state) do
    # Check if session is expired
    if state.session.expires_at &&
         DateTime.compare(DateTime.utc_now(), state.session.expires_at) == :gt do
      do_connect(state)
    else
      {:ok, state}
    end
  end

  defp build_resource_path(base_path, resource_id) do
    # Sanitize resource_id to be a valid path
    safe_id =
      resource_id
      |> String.replace(~r/[^a-zA-Z0-9\/_-]/, "_")

    base = String.trim_trailing(base_path, "/")
    "#{base}/#{safe_id}.json"
  end

  defp extract_resource_id(path, base_path) do
    base = String.trim_trailing(base_path, "/")

    cond do
      String.ends_with?(path, ".json") ->
        # Handle both full URLs and relative paths
        # Extract just the path part after the base_path
        path_part =
          if String.contains?(path, "://") do
            # Full URL - extract path after base_path
            uri = URI.parse(path)
            uri.path || path
          else
            path
          end

        # Find the base_path in the path and extract after it
        case :binary.match(path_part, base) do
          {start, len} ->
            path_part
            |> String.slice((start + len + 1)..-1//1)
            |> String.replace_suffix(".json", "")

          :nomatch ->
            # Fallback: just remove the .json suffix
            path_part
            |> String.replace_suffix(".json", "")
            |> Path.basename()
        end

      true ->
        nil
    end
  end

  defp ensure_containers(session, resource_path) do
    # Extract container paths and ensure they exist
    path_parts = String.split(resource_path, "/")
    # Remove the file name to get container path
    container_parts = Enum.drop(path_parts, -1)

    ensure_container_chain(session, container_parts, "")
  end

  defp ensure_container_chain(_session, [], _current), do: :ok

  defp ensure_container_chain(session, [part | rest], current) do
    container_path = if current == "", do: part, else: "#{current}/#{part}"

    # Try to create container (will succeed or already exist)
    case Client.create_container(session, container_path) do
      {:ok, _} ->
        ensure_container_chain(session, rest, container_path)

      {:error, {:create_container_failed, status, _}} when status in [409, 405] ->
        # Container already exists, continue
        ensure_container_chain(session, rest, container_path)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp list_resources_recursive(session, container_path, acc) do
    container = String.trim_trailing(container_path, "/") <> "/"

    case Client.list_container(session, container) do
      {:ok, resources} ->
        Enum.reduce_while(resources, {:ok, acc}, fn resource, {:ok, current_acc} ->
          if String.ends_with?(resource, "/") do
            # It's a container, recurse
            case list_resources_recursive(session, resource, current_acc) do
              {:ok, nested_acc} -> {:cont, {:ok, nested_acc}}
              error -> {:halt, error}
            end
          else
            # It's a resource
            {:cont, {:ok, [resource | current_acc]}}
          end
        end)

      {:error, :not_found} ->
        # Container doesn't exist yet
        {:ok, acc}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp to_iso8601(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp to_iso8601(str) when is_binary(str), do: str
  defp to_iso8601(_), do: DateTime.utc_now() |> DateTime.to_iso8601()

  defp parse_datetime(nil), do: nil

  defp parse_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end

  defp parse_datetime(_), do: nil
end
