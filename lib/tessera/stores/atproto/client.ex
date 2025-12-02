defmodule Tessera.Stores.ATProto.Client do
  @moduledoc """
  Low-level HTTP client for ATProto XRPC API calls.

  Handles authentication, session management, and API requests to
  ATProto Personal Data Servers (PDS).

  ## ATProto API Reference

  - [createSession](https://docs.bsky.app/docs/api/com-atproto-server-create-session)
  - [createRecord](https://docs.bsky.app/docs/api/com-atproto-repo-create-record)
  - [getRecord](https://docs.bsky.app/docs/api/com-atproto-repo-get-record)
  - [putRecord](https://docs.bsky.app/docs/api/com-atproto-repo-put-record)
  - [deleteRecord](https://docs.bsky.app/docs/api/com-atproto-repo-delete-record)
  - [listRecords](https://docs.bsky.app/docs/api/com-atproto-repo-list-records)
  """

  @default_pds_url "https://bsky.social"
  @tessera_collection "app.tessera.store.record"

  @type session :: %{
          access_jwt: String.t(),
          refresh_jwt: String.t(),
          did: String.t(),
          handle: String.t()
        }

  @type error :: {:error, term()}

  @doc """
  Creates a new authenticated session with the PDS.

  ## Parameters

  - `identifier` - Handle or DID (e.g., "user.bsky.social")
  - `password` - App password (not main account password)
  - `opts` - Options including `:pds_url`

  ## Returns

  - `{:ok, session}` on success
  - `{:error, reason}` on failure
  """
  @spec create_session(String.t(), String.t(), keyword()) :: {:ok, session()} | error()
  def create_session(identifier, password, opts \\ []) do
    pds_url = Keyword.get(opts, :pds_url, @default_pds_url)
    url = "#{pds_url}/xrpc/com.atproto.server.createSession"

    body = %{
      identifier: identifier,
      password: password
    }

    case http_client().post(url, json: body) do
      {:ok, %{status: 200, body: body}} ->
        {:ok,
         %{
           access_jwt: body["accessJwt"],
           refresh_jwt: body["refreshJwt"],
           did: body["did"],
           handle: body["handle"]
         }}

      {:ok, %{status: status, body: body}} ->
        {:error, {:auth_failed, status, body}}

      {:error, reason} ->
        {:error, {:network_error, reason}}
    end
  end

  @doc """
  Refreshes an existing session using the refresh token.
  """
  @spec refresh_session(String.t(), keyword()) :: {:ok, session()} | error()
  def refresh_session(refresh_jwt, opts \\ []) do
    pds_url = Keyword.get(opts, :pds_url, @default_pds_url)
    url = "#{pds_url}/xrpc/com.atproto.server.refreshSession"

    case http_client().post(url, auth: {:bearer, refresh_jwt}) do
      {:ok, %{status: 200, body: body}} ->
        {:ok,
         %{
           access_jwt: body["accessJwt"],
           refresh_jwt: body["refreshJwt"],
           did: body["did"],
           handle: body["handle"]
         }}

      {:ok, %{status: status, body: body}} ->
        {:error, {:refresh_failed, status, body}}

      {:error, reason} ->
        {:error, {:network_error, reason}}
    end
  end

  @doc """
  Creates a new record in the repository.

  ## Parameters

  - `session` - Authenticated session
  - `rkey` - Record key (unique identifier within the collection)
  - `record` - The record data to store
  - `opts` - Options including `:pds_url`, `:collection`
  """
  @spec create_record(session(), String.t(), map(), keyword()) :: {:ok, map()} | error()
  def create_record(session, rkey, record, opts \\ []) do
    pds_url = Keyword.get(opts, :pds_url, @default_pds_url)
    collection = Keyword.get(opts, :collection, @tessera_collection)
    url = "#{pds_url}/xrpc/com.atproto.repo.createRecord"

    body = %{
      repo: session.did,
      collection: collection,
      rkey: rkey,
      record: Map.put(record, "$type", collection)
    }

    case http_client().post(url, json: body, auth: {:bearer, session.access_jwt}) do
      {:ok, %{status: 200, body: response}} ->
        {:ok, response}

      {:ok, %{status: status, body: body}} ->
        {:error, {:create_failed, status, body}}

      {:error, reason} ->
        {:error, {:network_error, reason}}
    end
  end

  @doc """
  Creates or updates a record in the repository (upsert).

  ## Parameters

  - `session` - Authenticated session
  - `rkey` - Record key
  - `record` - The record data to store
  - `opts` - Options including `:pds_url`, `:collection`
  """
  @spec put_record(session(), String.t(), map(), keyword()) :: {:ok, map()} | error()
  def put_record(session, rkey, record, opts \\ []) do
    pds_url = Keyword.get(opts, :pds_url, @default_pds_url)
    collection = Keyword.get(opts, :collection, @tessera_collection)
    url = "#{pds_url}/xrpc/com.atproto.repo.putRecord"

    body = %{
      repo: session.did,
      collection: collection,
      rkey: rkey,
      record: Map.put(record, "$type", collection)
    }

    case http_client().post(url, json: body, auth: {:bearer, session.access_jwt}) do
      {:ok, %{status: 200, body: response}} ->
        {:ok, response}

      {:ok, %{status: status, body: body}} ->
        {:error, {:put_failed, status, body}}

      {:error, reason} ->
        {:error, {:network_error, reason}}
    end
  end

  @doc """
  Gets a record from the repository.

  ## Parameters

  - `session` - Authenticated session (can be nil for public records)
  - `did` - The DID of the repository owner
  - `rkey` - Record key
  - `opts` - Options including `:pds_url`, `:collection`
  """
  @spec get_record(session() | nil, String.t(), String.t(), keyword()) :: {:ok, map()} | error()
  def get_record(session, did, rkey, opts \\ []) do
    pds_url = Keyword.get(opts, :pds_url, @default_pds_url)
    collection = Keyword.get(opts, :collection, @tessera_collection)

    url = "#{pds_url}/xrpc/com.atproto.repo.getRecord"

    params = %{
      repo: did,
      collection: collection,
      rkey: rkey
    }

    request_opts =
      if session do
        [params: params, auth: {:bearer, session.access_jwt}]
      else
        [params: params]
      end

    case http_client().get(url, request_opts) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body}

      {:ok, %{status: 400, body: %{"error" => "RecordNotFound"}}} ->
        {:error, :not_found}

      {:ok, %{status: status, body: body}} ->
        {:error, {:get_failed, status, body}}

      {:error, reason} ->
        {:error, {:network_error, reason}}
    end
  end

  @doc """
  Deletes a record from the repository.

  ## Parameters

  - `session` - Authenticated session
  - `rkey` - Record key
  - `opts` - Options including `:pds_url`, `:collection`
  """
  @spec delete_record(session(), String.t(), keyword()) :: :ok | error()
  def delete_record(session, rkey, opts \\ []) do
    pds_url = Keyword.get(opts, :pds_url, @default_pds_url)
    collection = Keyword.get(opts, :collection, @tessera_collection)
    url = "#{pds_url}/xrpc/com.atproto.repo.deleteRecord"

    body = %{
      repo: session.did,
      collection: collection,
      rkey: rkey
    }

    case http_client().post(url, json: body, auth: {:bearer, session.access_jwt}) do
      {:ok, %{status: 200}} ->
        :ok

      {:ok, %{status: 400, body: %{"error" => "RecordNotFound"}}} ->
        {:error, :not_found}

      {:ok, %{status: status, body: body}} ->
        {:error, {:delete_failed, status, body}}

      {:error, reason} ->
        {:error, {:network_error, reason}}
    end
  end

  @doc """
  Lists records in a collection.

  ## Parameters

  - `session` - Authenticated session (can be nil for public records)
  - `did` - The DID of the repository owner
  - `opts` - Options including `:pds_url`, `:collection`, `:limit`, `:cursor`, `:reverse`
  """
  @spec list_records(session() | nil, String.t(), keyword()) :: {:ok, map()} | error()
  def list_records(session, did, opts \\ []) do
    pds_url = Keyword.get(opts, :pds_url, @default_pds_url)
    collection = Keyword.get(opts, :collection, @tessera_collection)
    limit = Keyword.get(opts, :limit, 100)
    cursor = Keyword.get(opts, :cursor)
    reverse = Keyword.get(opts, :reverse, false)

    url = "#{pds_url}/xrpc/com.atproto.repo.listRecords"

    params =
      %{
        repo: did,
        collection: collection,
        limit: limit,
        reverse: reverse
      }
      |> maybe_put(:cursor, cursor)

    request_opts =
      if session do
        [params: params, auth: {:bearer, session.access_jwt}]
      else
        [params: params]
      end

    case http_client().get(url, request_opts) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body}

      {:ok, %{status: status, body: body}} ->
        {:error, {:list_failed, status, body}}

      {:error, reason} ->
        {:error, {:network_error, reason}}
    end
  end

  @doc """
  Resolves a handle to a DID.
  """
  @spec resolve_handle(String.t(), keyword()) :: {:ok, String.t()} | error()
  def resolve_handle(handle, opts \\ []) do
    pds_url = Keyword.get(opts, :pds_url, @default_pds_url)
    url = "#{pds_url}/xrpc/com.atproto.identity.resolveHandle"

    case http_client().get(url, params: %{handle: handle}) do
      {:ok, %{status: 200, body: %{"did" => did}}} ->
        {:ok, did}

      {:ok, %{status: status, body: body}} ->
        {:error, {:resolve_failed, status, body}}

      {:error, reason} ->
        {:error, {:network_error, reason}}
    end
  end

  # Private helpers

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp http_client do
    Application.get_env(:tessera, :http_client, Tessera.HTTPClient)
  end
end
