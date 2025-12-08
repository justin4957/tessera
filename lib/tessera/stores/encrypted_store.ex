defmodule Tessera.Stores.EncryptedStore do
  @moduledoc """
  Encrypted storage wrapper that integrates TimeLockVault with storage adapters.

  Provides seamless encryption/decryption with temporal constraints at the
  storage layer. Data is automatically encrypted before storage and decrypted
  on retrieval, with time constraints validated during decryption.

  ## Architecture

  ```
  EncryptedStore
      │
      ├── TimeLockVault (encryption)
      │       └── Epoch-based keys with time constraints
      │
      └── Storage Adapter (persistence)
              └── Memory, Solid, ATProto, etc.
  ```

  ## Usage

      # Setup vault and storage
      {:ok, _vault} = TimeLockVault.start_link(name: :vault, conversation_key: key)
      {:ok, _store} = Memory.Adapter.start_link(name: :store)

      # Start encrypted store
      {:ok, _pid} = EncryptedStore.start_link(
        name: :encrypted_store,
        vault: :vault,
        store: :store
      )

      # Store with encryption (accessible until deadline)
      :ok = EncryptedStore.put_encrypted(
        :encrypted_store,
        "resource/1",
        "secret data",
        until: ~U[2024-12-31 23:59:59Z]
      )

      # Retrieve and decrypt (validates time constraints)
      {:ok, data, meta} = EncryptedStore.get_decrypted(:encrypted_store, "resource/1")

  ## Encryption Modes

  - `:until` - Data accessible only until the specified deadline
  - `:after` - Data accessible only after the specified release time
  - `:window` - Data accessible only within the specified time window
  - `:interval` - Data accessible during a TemporalInterval

  ## Metadata

  Encrypted data is stored with metadata including:
  - `:encrypted` - Boolean indicating data is encrypted
  - `:encryption_mode` - The time constraint mode used
  - `:constraints` - The time constraint parameters
  - `:encrypted_at` - When the data was encrypted
  """

  use GenServer

  alias Tessera.Crypto.TimeLockVault
  alias Tessera.Core.Rights.TemporalInterval

  @type resource_id :: String.t()
  @type encryption_opts :: [
          until: DateTime.t(),
          after: DateTime.t(),
          window: {DateTime.t(), DateTime.t()},
          interval: TemporalInterval.t()
        ]

  defstruct [:vault, :store, :default_mode]

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the encrypted store.

  ## Options

  - `:name` - GenServer name (required)
  - `:vault` - TimeLockVault server reference (required)
  - `:store` - Storage adapter server reference (required)
  - `:default_mode` - Default encryption mode (optional)
  """
  def start_link(opts) do
    name = Keyword.fetch!(opts, :name)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Stops the encrypted store.
  """
  def stop(server) do
    GenServer.stop(server)
  end

  @doc """
  Stores data with encryption and time constraints.

  ## Options

  - `:until` - Data accessible only until the specified deadline
  - `:after` - Data accessible only after the specified release time
  - `:window` - `{not_before, not_after}` tuple for time window
  - `:interval` - TemporalInterval for access constraints
  - `:metadata` - Additional metadata to store

  ## Examples

      # Accessible until deadline
      :ok = EncryptedStore.put_encrypted(server, "resource/1", data, until: deadline)

      # Accessible after release time
      :ok = EncryptedStore.put_encrypted(server, "resource/1", data, after: release_time)

      # Accessible within time window
      :ok = EncryptedStore.put_encrypted(server, "resource/1", data,
        window: {not_before, not_after})
  """
  @spec put_encrypted(GenServer.server(), resource_id(), binary(), encryption_opts()) ::
          :ok | {:error, term()}
  def put_encrypted(server, resource_id, data, opts \\ []) do
    GenServer.call(server, {:put_encrypted, resource_id, data, opts})
  end

  @doc """
  Retrieves and decrypts data.

  Validates time constraints during decryption. Returns an error if:
  - Data is not found
  - Time constraints are not satisfied (locked or expired)
  - Decryption fails

  ## Returns

  - `{:ok, data, metadata}` - Successfully decrypted
  - `{:error, :not_found}` - Resource does not exist
  - `{:error, :time_locked}` - Data not yet accessible
  - `{:error, :expired}` - Data access window has passed
  - `{:error, :not_encrypted}` - Data was stored without encryption
  """
  @spec get_decrypted(GenServer.server(), resource_id()) ::
          {:ok, binary(), map()} | {:error, term()}
  def get_decrypted(server, resource_id) do
    GenServer.call(server, {:get_decrypted, resource_id})
  end

  @doc """
  Stores data without encryption.

  Useful for data that doesn't need time constraints but should
  be managed through the same interface.
  """
  @spec put(GenServer.server(), resource_id(), term(), map()) ::
          :ok | {:error, term()}
  def put(server, resource_id, data, metadata \\ %{}) do
    GenServer.call(server, {:put, resource_id, data, metadata})
  end

  @doc """
  Retrieves data (encrypted or unencrypted).

  For encrypted data, performs decryption with time validation.
  For unencrypted data, returns directly.
  """
  @spec get(GenServer.server(), resource_id()) ::
          {:ok, term(), map()} | {:error, term()}
  def get(server, resource_id) do
    GenServer.call(server, {:get, resource_id})
  end

  @doc """
  Deletes data by resource ID.
  """
  @spec delete(GenServer.server(), resource_id()) ::
          :ok | {:error, term()}
  def delete(server, resource_id) do
    GenServer.call(server, {:delete, resource_id})
  end

  @doc """
  Lists resources, optionally filtered by prefix.
  """
  @spec list(GenServer.server(), String.t() | nil) ::
          {:ok, [resource_id()]} | {:error, term()}
  def list(server, prefix \\ nil) do
    GenServer.call(server, {:list, prefix})
  end

  @doc """
  Checks if a resource exists.
  """
  @spec exists?(GenServer.server(), resource_id()) :: boolean()
  def exists?(server, resource_id) do
    GenServer.call(server, {:exists?, resource_id})
  end

  @doc """
  Checks if encrypted data is currently accessible.

  Returns `true` if the data can be decrypted now, `false` otherwise.
  """
  @spec accessible?(GenServer.server(), resource_id()) :: boolean()
  def accessible?(server, resource_id) do
    GenServer.call(server, {:accessible?, resource_id})
  end

  @doc """
  Inspects encryption metadata without decrypting.

  Returns information about the encryption constraints.
  """
  @spec inspect_encryption(GenServer.server(), resource_id()) ::
          {:ok, map()} | {:error, term()}
  def inspect_encryption(server, resource_id) do
    GenServer.call(server, {:inspect_encryption, resource_id})
  end

  @doc """
  Returns information about the encrypted store.
  """
  @spec info(GenServer.server()) :: map()
  def info(server) do
    GenServer.call(server, :info)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl GenServer
  def init(opts) do
    vault = Keyword.fetch!(opts, :vault)
    store = Keyword.fetch!(opts, :store)
    default_mode = Keyword.get(opts, :default_mode)

    state = %__MODULE__{
      vault: vault,
      store: store,
      default_mode: default_mode
    }

    {:ok, state}
  end

  @impl GenServer
  def handle_call({:put_encrypted, resource_id, data, opts}, _from, state) do
    result = do_put_encrypted(state, resource_id, data, opts)
    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:get_decrypted, resource_id}, _from, state) do
    result = do_get_decrypted(state, resource_id)
    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:put, resource_id, data, metadata}, _from, state) do
    enriched_metadata = Map.put(metadata, :encrypted, false)
    result = store_put(state.store, resource_id, data, enriched_metadata)
    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:get, resource_id}, _from, state) do
    result =
      case store_get(state.store, resource_id) do
        {:ok, data, %{encrypted: true} = metadata} ->
          do_decrypt(state, data, metadata)

        {:ok, data, metadata} ->
          {:ok, data, metadata}

        error ->
          error
      end

    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:delete, resource_id}, _from, state) do
    result = store_delete(state.store, resource_id)
    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:list, prefix}, _from, state) do
    result = store_list(state.store, prefix)
    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:exists?, resource_id}, _from, state) do
    result = store_exists?(state.store, resource_id)
    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:accessible?, resource_id}, _from, state) do
    result =
      case store_get(state.store, resource_id) do
        {:ok, sealed_data, %{encrypted: true}} ->
          TimeLockVault.accessible?(state.vault, sealed_data)

        {:ok, _data, _metadata} ->
          true

        {:error, _} ->
          false
      end

    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:inspect_encryption, resource_id}, _from, state) do
    result =
      case store_get(state.store, resource_id) do
        {:ok, sealed_data, %{encrypted: true} = metadata} ->
          case TimeLockVault.inspect(state.vault, sealed_data) do
            {:ok, vault_info} ->
              {:ok, Map.merge(metadata, %{vault_info: vault_info})}

            error ->
              error
          end

        {:ok, _data, metadata} ->
          {:ok, Map.put(metadata, :encrypted, false)}

        error ->
          error
      end

    {:reply, result, state}
  end

  @impl GenServer
  def handle_call(:info, _from, state) do
    store_info = store_info(state.store)

    info = %{
      type: :encrypted_store,
      vault: state.vault,
      store: state.store,
      store_info: store_info,
      capabilities: [
        :encrypted_storage,
        :time_constraints,
        :transparent_decryption
      ]
    }

    {:reply, info, state}
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp do_put_encrypted(state, resource_id, data, opts) do
    user_metadata = Keyword.get(opts, :metadata, %{})

    with {:ok, mode, constraints} <- parse_encryption_opts(opts, state.default_mode),
         {:ok, sealed_data} <- seal_data(state.vault, data, mode, constraints) do
      metadata =
        Map.merge(user_metadata, %{
          encrypted: true,
          encryption_mode: mode,
          constraints: serialize_constraints(mode, constraints),
          encrypted_at: DateTime.utc_now()
        })

      store_put(state.store, resource_id, sealed_data, metadata)
    end
  end

  defp do_get_decrypted(state, resource_id) do
    case store_get(state.store, resource_id) do
      {:ok, sealed_data, %{encrypted: true} = metadata} ->
        do_decrypt(state, sealed_data, metadata)

      {:ok, _data, %{encrypted: false}} ->
        {:error, :not_encrypted}

      {:ok, _data, _metadata} ->
        {:error, :not_encrypted}

      error ->
        error
    end
  end

  defp do_decrypt(state, sealed_data, metadata) do
    case TimeLockVault.unseal(state.vault, sealed_data) do
      {:ok, plaintext} ->
        {:ok, plaintext, metadata}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp parse_encryption_opts(opts, default_mode) do
    cond do
      until = Keyword.get(opts, :until) ->
        {:ok, :until, until}

      after_time = Keyword.get(opts, :after) ->
        {:ok, :after, after_time}

      window = Keyword.get(opts, :window) ->
        case window do
          {not_before, not_after} -> {:ok, :window, {not_before, not_after}}
          _ -> {:error, :invalid_window}
        end

      interval = Keyword.get(opts, :interval) ->
        {:ok, :interval, interval}

      default_mode == :until ->
        # Default to 30 days from now
        deadline = DateTime.add(DateTime.utc_now(), 30 * 24 * 3600, :second)
        {:ok, :until, deadline}

      default_mode != nil ->
        {:error, :missing_encryption_constraints}

      true ->
        {:error, :missing_encryption_constraints}
    end
  end

  defp seal_data(vault, data, :until, deadline) do
    TimeLockVault.seal_until(vault, data, deadline)
  end

  defp seal_data(vault, data, :after, release_time) do
    TimeLockVault.seal_after(vault, data, release_time)
  end

  defp seal_data(vault, data, :window, {not_before, not_after}) do
    TimeLockVault.seal_window(vault, data, not_before, not_after)
  end

  defp seal_data(vault, data, :interval, interval) do
    TimeLockVault.seal_for_interval(vault, data, interval)
  end

  defp serialize_constraints(:until, deadline) do
    %{until: DateTime.to_iso8601(deadline)}
  end

  defp serialize_constraints(:after, release_time) do
    %{after: DateTime.to_iso8601(release_time)}
  end

  defp serialize_constraints(:window, {not_before, not_after}) do
    %{
      not_before: DateTime.to_iso8601(not_before),
      not_after: DateTime.to_iso8601(not_after)
    }
  end

  defp serialize_constraints(:interval, interval) do
    %{
      start_time: DateTime.to_iso8601(interval.start_time),
      end_time: if(interval.end_time, do: DateTime.to_iso8601(interval.end_time))
    }
  end

  # Storage adapter calls - handle both module and GenServer reference
  defp store_put(store, resource_id, data, metadata) do
    if is_atom(store) and function_exported?(store, :put, 4) do
      store.put(resource_id, data, metadata, store)
    else
      GenServer.call(store, {:put, resource_id, data, metadata})
    end
  end

  defp store_get(store, resource_id) do
    if is_atom(store) and function_exported?(store, :get, 2) do
      store.get(resource_id, store)
    else
      GenServer.call(store, {:get, resource_id})
    end
  end

  defp store_delete(store, resource_id) do
    if is_atom(store) and function_exported?(store, :delete, 2) do
      store.delete(resource_id, store)
    else
      GenServer.call(store, {:delete, resource_id})
    end
  end

  defp store_list(store, prefix) do
    if is_atom(store) and function_exported?(store, :list, 2) do
      store.list(prefix, store)
    else
      GenServer.call(store, {:list, prefix})
    end
  end

  defp store_exists?(store, resource_id) do
    if is_atom(store) and function_exported?(store, :exists?, 2) do
      store.exists?(resource_id, store)
    else
      GenServer.call(store, {:exists?, resource_id})
    end
  end

  defp store_info(store) do
    if is_atom(store) and function_exported?(store, :info, 1) do
      store.info(store)
    else
      GenServer.call(store, :info)
    end
  end
end
