defmodule Tessera.Crypto.TimeLockVault do
  @moduledoc """
  High-level time-lock encryption with automatic key management.

  Combines `TimeLock` encryption with `EpochManager` key rotation to provide
  a complete solution for temporal data sovereignty. Data is encrypted with
  epoch-derived keys and time constraints, enabling:

  - Automatic key rotation at epoch boundaries
  - Forward secrecy (old epoch keys can be deleted)
  - Time-bounded access windows
  - Seamless integration with the Grant system

  ## Architecture

  ```
  TimeLockVault
      │
      ├── EpochManager (key rotation)
      │       └── Epoch Keys (time-bounded)
      │
      └── TimeLock (encryption primitives)
              └── AES-256-GCM with temporal AAD
  ```

  ## Usage

      # Setup
      {:ok, root_key} = KeyDerivation.generate_root_key()
      {:ok, conv_key} = KeyDerivation.derive_conversation_key(root_key, "vault")

      {:ok, _pid} = TimeLockVault.start_link(
        name: :my_vault,
        conversation_key: conv_key,
        duration: :hour
      )

      # Encrypt with time constraints
      {:ok, sealed} = TimeLockVault.seal_until(
        :my_vault,
        "secret data",
        ~U[2024-12-31 23:59:59Z]
      )

      # Decrypt (validates time + uses correct epoch key)
      {:ok, plaintext} = TimeLockVault.unseal(:my_vault, sealed)
  """

  use GenServer

  alias Tessera.Crypto.{EpochManager, KeyDerivation, TimeLock}
  alias Tessera.Crypto.Keys.MessageKey
  alias Tessera.Core.Rights.TemporalInterval

  defstruct [
    :epoch_manager,
    :conversation_key,
    :duration
  ]

  @type sealed_data :: binary()

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the TimeLockVault.

  ## Options

  - `:name` - GenServer name (required)
  - `:conversation_key` - The conversation key for derivation (required)
  - `:duration` - Epoch duration (default: `:hour`)
  - `:retention_epochs` - Number of epochs to retain (default: 168)
  """
  def start_link(opts) do
    name = Keyword.fetch!(opts, :name)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Seals data to be accessible only until the specified deadline.

  The data is encrypted with a message key derived from the current epoch,
  with time constraints embedded in the ciphertext.

  ## Examples

      {:ok, sealed} = TimeLockVault.seal_until(:vault, "data", ~U[2024-12-31 23:59:59Z])
  """
  @spec seal_until(GenServer.server(), binary(), DateTime.t(), keyword()) ::
          {:ok, sealed_data()} | {:error, term()}
  def seal_until(server, plaintext, deadline, opts \\ []) do
    GenServer.call(server, {:seal_until, plaintext, deadline, opts})
  end

  @doc """
  Seals data to be accessible only after the specified release time.

  ## Examples

      {:ok, sealed} = TimeLockVault.seal_after(:vault, "embargoed", ~U[2024-06-01 00:00:00Z])
  """
  @spec seal_after(GenServer.server(), binary(), DateTime.t(), keyword()) ::
          {:ok, sealed_data()} | {:error, term()}
  def seal_after(server, plaintext, release_time, opts \\ []) do
    GenServer.call(server, {:seal_after, plaintext, release_time, opts})
  end

  @doc """
  Seals data to be accessible only within the specified time window.

  ## Examples

      {:ok, sealed} = TimeLockVault.seal_window(
        :vault,
        "limited access",
        ~U[2024-01-01 00:00:00Z],
        ~U[2024-03-31 23:59:59Z]
      )
  """
  @spec seal_window(GenServer.server(), binary(), DateTime.t(), DateTime.t(), keyword()) ::
          {:ok, sealed_data()} | {:error, term()}
  def seal_window(server, plaintext, not_before, not_after, opts \\ []) do
    GenServer.call(server, {:seal_window, plaintext, not_before, not_after, opts})
  end

  @doc """
  Seals data using a TemporalInterval for access constraints.

  ## Examples

      interval = TemporalInterval.for_duration(30, :day)
      {:ok, sealed} = TimeLockVault.seal_for_interval(:vault, "data", interval)
  """
  @spec seal_for_interval(GenServer.server(), binary(), TemporalInterval.t(), keyword()) ::
          {:ok, sealed_data()} | {:error, term()}
  def seal_for_interval(server, plaintext, %TemporalInterval{} = interval, opts \\ []) do
    GenServer.call(server, {:seal_for_interval, plaintext, interval, opts})
  end

  @doc """
  Unseals (decrypts) time-locked data.

  Validates both the time constraints and uses the appropriate epoch key
  for decryption.

  ## Returns

  - `{:ok, plaintext}` - Decryption successful
  - `{:error, :time_locked}` - Current time is before the access window
  - `{:error, :expired}` - Current time is after the access window
  - `{:error, :epoch_expired}` - The epoch key has been rotated out
  - `{:error, :decryption_failed}` - Decryption failed (wrong key, tampered)

  ## Examples

      {:ok, plaintext} = TimeLockVault.unseal(:vault, sealed_data)
  """
  @spec unseal(GenServer.server(), sealed_data()) ::
          {:ok, binary()} | {:error, term()}
  def unseal(server, sealed_data) do
    GenServer.call(server, {:unseal, sealed_data})
  end

  @doc """
  Checks if sealed data is currently accessible.

  ## Examples

      TimeLockVault.accessible?(:vault, sealed_data)
      # => true
  """
  @spec accessible?(GenServer.server(), sealed_data()) :: boolean()
  def accessible?(server, sealed_data) do
    GenServer.call(server, {:accessible?, sealed_data})
  end

  @doc """
  Inspects sealed data to get its metadata without decrypting.

  ## Examples

      {:ok, info} = TimeLockVault.inspect(:vault, sealed_data)
      # => {:ok, %{epoch: 42, type: :window, not_before: ~U[...], not_after: ~U[...]}}
  """
  @spec inspect(GenServer.server(), sealed_data()) :: {:ok, map()} | {:error, term()}
  def inspect(server, sealed_data) do
    GenServer.call(server, {:inspect, sealed_data})
  end

  @doc """
  Stops the vault.
  """
  @spec stop(GenServer.server()) :: :ok
  def stop(server) do
    GenServer.stop(server)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl GenServer
  def init(opts) do
    conversation_key = Keyword.fetch!(opts, :conversation_key)
    duration = Keyword.get(opts, :duration, :hour)
    retention_epochs = Keyword.get(opts, :retention_epochs, 168)
    name = Keyword.fetch!(opts, :name)

    # Start embedded epoch manager
    epoch_manager_name = :"#{name}_epoch_manager"

    {:ok, _pid} =
      EpochManager.start_link(
        name: epoch_manager_name,
        conversation_key: conversation_key,
        duration: duration,
        retention_epochs: retention_epochs,
        auto_rotate: true
      )

    state = %__MODULE__{
      epoch_manager: epoch_manager_name,
      conversation_key: conversation_key,
      duration: duration
    }

    {:ok, state}
  end

  @impl GenServer
  def handle_call({:seal_until, plaintext, deadline, opts}, _from, state) do
    result =
      do_seal(state, plaintext, opts, fn key ->
        TimeLock.encrypt_until(plaintext, deadline, key)
      end)

    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:seal_after, plaintext, release_time, opts}, _from, state) do
    result =
      do_seal(state, plaintext, opts, fn key ->
        TimeLock.encrypt_after(plaintext, release_time, key)
      end)

    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:seal_window, plaintext, not_before, not_after, opts}, _from, state) do
    result =
      do_seal(state, plaintext, opts, fn key ->
        TimeLock.encrypt_window(plaintext, not_before, not_after, key)
      end)

    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:seal_for_interval, plaintext, interval, opts}, _from, state) do
    result =
      do_seal(state, plaintext, opts, fn key ->
        TimeLock.encrypt_for_interval(plaintext, interval, key)
      end)

    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:unseal, sealed_data}, _from, state) do
    result = do_unseal(state, sealed_data)
    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:accessible?, sealed_data}, _from, state) do
    result =
      case parse_sealed_data(sealed_data) do
        {:ok, _epoch, ciphertext} ->
          TimeLock.accessible?(ciphertext)

        {:error, _} ->
          false
      end

    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:inspect, sealed_data}, _from, state) do
    result =
      with {:ok, epoch, ciphertext} <- parse_sealed_data(sealed_data),
           {:ok, time_info} <- TimeLock.inspect_constraints(ciphertext) do
        {:ok, Map.put(time_info, :epoch, epoch)}
      end

    {:reply, result, state}
  end

  @impl GenServer
  def terminate(_reason, state) do
    # Stop the embedded epoch manager
    try do
      EpochManager.stop(state.epoch_manager)
    catch
      :exit, _ -> :ok
    end

    :ok
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp do_seal(state, _plaintext, opts, encrypt_fn) do
    resource_id = Keyword.get(opts, :resource_id, generate_resource_id())

    with {:ok, epoch_key} <- EpochManager.current_key(state.epoch_manager),
         {:ok, message_key} <- KeyDerivation.derive_message_key(epoch_key, resource_id),
         key_bytes = MessageKey.to_bytes(message_key),
         {:ok, ciphertext} <- encrypt_fn.(key_bytes) do
      epoch = epoch_key.epoch_number
      sealed = build_sealed_data(epoch, resource_id, ciphertext)
      {:ok, sealed}
    end
  end

  defp do_unseal(state, sealed_data) do
    with {:ok, epoch, resource_id, ciphertext} <- parse_sealed_data_full(sealed_data),
         {:ok, epoch_key} <- get_epoch_key(state, epoch),
         {:ok, message_key} <- KeyDerivation.derive_message_key(epoch_key, resource_id),
         key_bytes = MessageKey.to_bytes(message_key) do
      TimeLock.decrypt(ciphertext, key_bytes)
    end
  end

  defp get_epoch_key(state, epoch) do
    case EpochManager.get_key(epoch, state.epoch_manager) do
      {:ok, _} = result -> result
      {:error, :expired} -> {:error, :epoch_expired}
      {:error, _} = error -> error
    end
  end

  defp build_sealed_data(epoch, resource_id, ciphertext) do
    resource_id_bytes = byte_size(resource_id)

    <<
      "TLVAULT1",
      epoch::32,
      resource_id_bytes::16,
      resource_id::binary,
      ciphertext::binary
    >>
  end

  defp parse_sealed_data(<<"TLVAULT1", epoch::32, rest::binary>> = sealed) do
    _ = rest
    {:ok, epoch, extract_ciphertext(sealed)}
  end

  defp parse_sealed_data(_), do: {:error, :invalid_sealed_data}

  defp parse_sealed_data_full(<<"TLVAULT1", epoch::32, resource_id_len::16, rest::binary>>) do
    <<resource_id::binary-size(resource_id_len), ciphertext::binary>> = rest
    {:ok, epoch, resource_id, ciphertext}
  end

  defp parse_sealed_data_full(_), do: {:error, :invalid_sealed_data}

  defp extract_ciphertext(<<"TLVAULT1", _epoch::32, resource_id_len::16, rest::binary>>) do
    <<_resource_id::binary-size(resource_id_len), ciphertext::binary>> = rest
    ciphertext
  end

  defp generate_resource_id do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end
end
