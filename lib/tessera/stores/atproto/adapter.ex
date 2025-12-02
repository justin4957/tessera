defmodule Tessera.Stores.ATProto.Adapter do
  @moduledoc """
  ATProto Personal Data Server (PDS) storage adapter for Tessera.

  Implements the `Tessera.Store` behaviour using ATProto's repository
  system for data storage. This enables Tessera to use Bluesky's
  decentralized infrastructure as a storage backend.

  ## Configuration

  Configure the adapter in your config:

      config :tessera, Tessera.Stores.ATProto.Adapter,
        pds_url: "https://bsky.social",
        identifier: "your-handle.bsky.social",
        password: System.get_env("ATPROTO_APP_PASSWORD")

  ## Usage

      # Start the adapter
      {:ok, pid} = Tessera.Stores.ATProto.Adapter.start_link(
        name: :my_atproto_store,
        identifier: "user.bsky.social",
        password: "app-password-here"
      )

      # Store data
      :ok = Tessera.Stores.ATProto.Adapter.put(
        "my-resource-key",
        %{name: "test", value: 123},
        %{},
        :my_atproto_store
      )

      # Retrieve data
      {:ok, data, metadata} = Tessera.Stores.ATProto.Adapter.get(
        "my-resource-key",
        :my_atproto_store
      )

  ## Resource ID Mapping

  Resource IDs are mapped to ATProto record keys (rkeys). The adapter
  uses URL-safe base64 encoding to handle resource IDs that may contain
  characters not allowed in rkeys.

  ## ATProto Specifics

  - Uses `app.tessera.store.record` as the default Lexicon collection
  - Records are stored with automatic `$type` field
  - Supports both create and upsert operations
  - Handles session refresh automatically
  """

  use GenServer
  @behaviour Tessera.Store

  alias Tessera.Stores.ATProto.Client

  @default_collection "app.tessera.store.record"

  defstruct [
    :session,
    :pds_url,
    :identifier,
    :password,
    :collection
  ]

  # Client API

  @doc """
  Starts the ATProto adapter as a GenServer.

  ## Options

  - `:name` - GenServer name (default: `__MODULE__`)
  - `:pds_url` - PDS URL (default: "https://bsky.social")
  - `:identifier` - Handle or DID for authentication
  - `:password` - App password for authentication
  - `:collection` - Lexicon collection NSID (default: "app.tessera.store.record")
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
      pds_url: Keyword.get(opts, :pds_url, "https://bsky.social"),
      identifier: Keyword.get(opts, :identifier),
      password: Keyword.get(opts, :password),
      collection: Keyword.get(opts, :collection, @default_collection),
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
  def handle_call({:put, resource_id, data, metadata}, _from, state) do
    with {:ok, state} <- ensure_session(state) do
      rkey = encode_rkey(resource_id)
      timestamp = DateTime.utc_now() |> DateTime.to_iso8601()

      record = %{
        "resourceId" => resource_id,
        "data" => data,
        "metadata" => metadata,
        "createdAt" => Map.get(metadata, :created_at, timestamp) |> to_iso8601(),
        "updatedAt" => timestamp
      }

      opts = [pds_url: state.pds_url, collection: state.collection]

      case Client.put_record(state.session, rkey, record, opts) do
        {:ok, _response} ->
          {:reply, :ok, state}

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
      rkey = encode_rkey(resource_id)
      opts = [pds_url: state.pds_url, collection: state.collection]

      case Client.get_record(state.session, state.session.did, rkey, opts) do
        {:ok, %{"value" => record}} ->
          data = record["data"]

          metadata = %{
            created_at: parse_datetime(record["createdAt"]),
            updated_at: parse_datetime(record["updatedAt"]),
            atproto: Map.get(record, "metadata", %{})
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
      rkey = encode_rkey(resource_id)
      opts = [pds_url: state.pds_url, collection: state.collection]

      case Client.delete_record(state.session, rkey, opts) do
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
      opts = [pds_url: state.pds_url, collection: state.collection, limit: 100]

      case list_all_records(state.session, state.session.did, opts, [], nil) do
        {:ok, records} ->
          resource_ids =
            records
            |> Enum.map(fn record -> record["value"]["resourceId"] end)
            |> Enum.filter(fn id -> prefix == nil || String.starts_with?(id, prefix) end)
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
      rkey = encode_rkey(resource_id)
      opts = [pds_url: state.pds_url, collection: state.collection]

      result =
        case Client.get_record(state.session, state.session.did, rkey, opts) do
          {:ok, _} -> true
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
      type: :atproto,
      pds_url: state.pds_url,
      collection: state.collection,
      did: state.session && state.session.did,
      handle: state.session && state.session.handle,
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
      | identifier: Keyword.get(opts, :identifier, state.identifier),
        password: Keyword.get(opts, :password, state.password),
        pds_url: Keyword.get(opts, :pds_url, state.pds_url)
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

  defp do_connect(%{identifier: nil}), do: {:error, :missing_identifier}
  defp do_connect(%{password: nil}), do: {:error, :missing_password}

  defp do_connect(state) do
    case Client.create_session(state.identifier, state.password, pds_url: state.pds_url) do
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
    {:ok, state}
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

  defp encode_rkey(resource_id) do
    resource_id
    |> Base.url_encode64(padding: false)
    |> String.replace(~r/[^a-zA-Z0-9._:~-]/, "_")
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
