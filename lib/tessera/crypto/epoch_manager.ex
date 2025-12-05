defmodule Tessera.Crypto.EpochManager do
  @moduledoc """
  Manages epoch-based key rotation for temporal data sovereignty.

  The EpochManager is a GenServer that:
  - Tracks the current epoch and automatically rotates at boundaries
  - Maintains a history of epoch keys for backward decryption
  - Provides key lookup by epoch number or timestamp
  - Supports configurable retention policies

  ## Architecture

  ```
  EpochManager
      │
      ├── Current Epoch Key (active for encryption)
      │
      └── Key History (for decryption of historical data)
              ├── Epoch N-1 Key
              ├── Epoch N-2 Key
              └── ... (bounded by retention policy)
  ```

  ## Usage

      # Start the manager
      {:ok, pid} = EpochManager.start_link(
        name: :my_epoch_manager,
        conversation_key: conv_key,
        duration: :hour,
        retention_epochs: 24
      )

      # Get current epoch key for encryption
      {:ok, epoch_key} = EpochManager.current_key(:my_epoch_manager)

      # Get key for a specific epoch (decryption)
      {:ok, epoch_key} = EpochManager.get_key(5, :my_epoch_manager)

      # Get key for a timestamp
      {:ok, epoch_key} = EpochManager.key_for_time(~U[2024-06-15 14:30:00Z], :my_epoch_manager)

      # Force rotation (for testing or manual control)
      {:ok, new_epoch} = EpochManager.rotate_now(:my_epoch_manager)
  """

  use GenServer

  alias Tessera.Crypto.{Epoch, KeyDerivation}
  alias Tessera.Crypto.Keys.{ConversationKey, EpochKey}

  @default_duration :hour
  @default_retention_epochs 168
  @rotation_check_interval 1000

  defstruct [
    :conversation_key,
    :duration,
    :current_epoch,
    :retention_epochs,
    :epoch_zero,
    :key_cache,
    :rotation_timer
  ]

  @type t :: %__MODULE__{
          conversation_key: ConversationKey.t(),
          duration: Epoch.duration(),
          current_epoch: Epoch.epoch_id(),
          retention_epochs: pos_integer(),
          epoch_zero: DateTime.t(),
          key_cache: %{Epoch.epoch_id() => EpochKey.t()},
          rotation_timer: reference() | nil
        }

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the EpochManager.

  ## Options

  - `:name` - GenServer name (required)
  - `:conversation_key` - The conversation key to derive epoch keys from (required)
  - `:duration` - Epoch duration (`:hour`, `:day`, `:week`, or seconds, default: `:hour`)
  - `:retention_epochs` - Number of past epochs to retain keys for (default: 168 = 1 week of hours)
  - `:epoch_zero` - Reference point for epoch 0 (default: Unix epoch)
  - `:auto_rotate` - Whether to automatically rotate at epoch boundaries (default: true)
  """
  def start_link(opts) do
    name = Keyword.fetch!(opts, :name)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Returns the current epoch key for encryption.

  ## Examples

      {:ok, epoch_key} = EpochManager.current_key(:my_manager)
  """
  @spec current_key(GenServer.server()) :: {:ok, EpochKey.t()}
  def current_key(server) do
    GenServer.call(server, :current_key)
  end

  @doc """
  Returns the current epoch number.

  ## Examples

      epoch_id = EpochManager.current_epoch(:my_manager)
  """
  @spec current_epoch(GenServer.server()) :: Epoch.epoch_id()
  def current_epoch(server) do
    GenServer.call(server, :current_epoch)
  end

  @doc """
  Returns the key for a specific epoch number.

  Returns `{:error, :expired}` if the epoch is older than the retention window.
  Returns `{:error, :future_epoch}` if the epoch hasn't occurred yet.

  ## Examples

      {:ok, epoch_key} = EpochManager.get_key(42, :my_manager)
      {:error, :expired} = EpochManager.get_key(1, :my_manager)
  """
  @spec get_key(Epoch.epoch_id(), GenServer.server()) ::
          {:ok, EpochKey.t()} | {:error, :expired | :future_epoch | :invalid_epoch}
  def get_key(epoch_id, server) do
    GenServer.call(server, {:get_key, epoch_id})
  end

  @doc """
  Returns the key for a specific timestamp.

  ## Examples

      {:ok, epoch_key} = EpochManager.key_for_time(~U[2024-06-15 14:30:00Z], :my_manager)
  """
  @spec key_for_time(DateTime.t(), GenServer.server()) ::
          {:ok, EpochKey.t()} | {:error, :expired | :future_epoch}
  def key_for_time(%DateTime{} = time, server) do
    GenServer.call(server, {:key_for_time, time})
  end

  @doc """
  Forces an immediate rotation to the next epoch.

  This is useful for testing or when manual key rotation is required.
  Note: This advances to the *calculated* current epoch, not necessarily
  the next sequential number.

  ## Examples

      {:ok, new_epoch_id} = EpochManager.rotate_now(:my_manager)
  """
  @spec rotate_now(GenServer.server()) :: {:ok, Epoch.epoch_id()}
  def rotate_now(server) do
    GenServer.call(server, :rotate_now)
  end

  @doc """
  Returns information about the manager's current state.

  ## Examples

      info = EpochManager.info(:my_manager)
      # => %{
      #   current_epoch: 42,
      #   duration: :hour,
      #   retention_epochs: 168,
      #   cached_epochs: [40, 41, 42],
      #   oldest_available: 40,
      #   time_until_rotation: 1847
      # }
  """
  @spec info(GenServer.server()) :: map()
  def info(server) do
    GenServer.call(server, :info)
  end

  @doc """
  Returns the list of epoch IDs currently available (cached).

  ## Examples

      epochs = EpochManager.available_epochs(:my_manager)
      # => [40, 41, 42]
  """
  @spec available_epochs(GenServer.server()) :: [Epoch.epoch_id()]
  def available_epochs(server) do
    GenServer.call(server, :available_epochs)
  end

  @doc """
  Manually purges expired epochs from the cache.

  This is called automatically during rotation, but can be triggered
  manually if needed.
  """
  @spec purge_expired(GenServer.server()) :: :ok
  def purge_expired(server) do
    GenServer.cast(server, :purge_expired)
  end

  @doc """
  Stops the epoch manager.
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
    duration = Keyword.get(opts, :duration, @default_duration)
    retention_epochs = Keyword.get(opts, :retention_epochs, @default_retention_epochs)
    epoch_zero = Keyword.get(opts, :epoch_zero, ~U[1970-01-01 00:00:00Z])
    auto_rotate = Keyword.get(opts, :auto_rotate, true)

    epoch_opts = [epoch_zero: epoch_zero]
    current_epoch = Epoch.current_epoch(duration, epoch_opts)

    # Initialize with current epoch key
    {:ok, current_key} = KeyDerivation.derive_epoch_key(conversation_key, current_epoch)

    state = %__MODULE__{
      conversation_key: conversation_key,
      duration: duration,
      current_epoch: current_epoch,
      retention_epochs: retention_epochs,
      epoch_zero: epoch_zero,
      key_cache: %{current_epoch => current_key},
      rotation_timer: nil
    }

    # Schedule rotation check if auto_rotate is enabled
    state =
      if auto_rotate do
        schedule_rotation_check(state)
      else
        state
      end

    {:ok, state}
  end

  @impl GenServer
  def handle_call(:current_key, _from, state) do
    key = Map.fetch!(state.key_cache, state.current_epoch)
    {:reply, {:ok, key}, state}
  end

  @impl GenServer
  def handle_call(:current_epoch, _from, state) do
    {:reply, state.current_epoch, state}
  end

  @impl GenServer
  def handle_call({:get_key, epoch_id}, _from, state) do
    result = fetch_or_derive_key(state, epoch_id)
    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:key_for_time, time}, _from, state) do
    epoch_opts = [epoch_zero: state.epoch_zero]
    epoch_id = Epoch.epoch_for_time(time, state.duration, epoch_opts)
    result = fetch_or_derive_key(state, epoch_id)
    {:reply, result, state}
  end

  @impl GenServer
  def handle_call(:rotate_now, _from, state) do
    {:ok, new_state} = do_rotation(state)
    {:reply, {:ok, new_state.current_epoch}, new_state}
  end

  @impl GenServer
  def handle_call(:info, _from, state) do
    epoch_opts = [epoch_zero: state.epoch_zero]
    cached_epochs = Map.keys(state.key_cache) |> Enum.sort()

    info = %{
      current_epoch: state.current_epoch,
      duration: state.duration,
      retention_epochs: state.retention_epochs,
      cached_epochs: cached_epochs,
      oldest_available: oldest_available_epoch(state),
      time_until_rotation: Epoch.time_until_rotation(state.duration, epoch_opts)
    }

    {:reply, info, state}
  end

  @impl GenServer
  def handle_call(:available_epochs, _from, state) do
    epochs = Map.keys(state.key_cache) |> Enum.sort()
    {:reply, epochs, state}
  end

  @impl GenServer
  def handle_cast(:purge_expired, state) do
    {:noreply, purge_expired_keys(state)}
  end

  @impl GenServer
  def handle_info(:check_rotation, state) do
    epoch_opts = [epoch_zero: state.epoch_zero]
    actual_epoch = Epoch.current_epoch(state.duration, epoch_opts)

    new_state =
      if actual_epoch > state.current_epoch do
        {:ok, rotated_state} = do_rotation(state)
        rotated_state
      else
        state
      end

    {:noreply, schedule_rotation_check(new_state)}
  end

  @impl GenServer
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp fetch_or_derive_key(state, epoch_id) do
    cond do
      not Epoch.valid_epoch_id?(epoch_id) ->
        {:error, :invalid_epoch}

      epoch_id > state.current_epoch ->
        {:error, :future_epoch}

      epoch_id < oldest_available_epoch(state) ->
        {:error, :expired}

      Map.has_key?(state.key_cache, epoch_id) ->
        {:ok, Map.fetch!(state.key_cache, epoch_id)}

      true ->
        # Derive the key on-demand for epochs within retention window
        KeyDerivation.derive_epoch_key(state.conversation_key, epoch_id)
    end
  end

  defp oldest_available_epoch(state) do
    max(0, state.current_epoch - state.retention_epochs + 1)
  end

  defp do_rotation(state) do
    epoch_opts = [epoch_zero: state.epoch_zero]
    new_epoch = Epoch.current_epoch(state.duration, epoch_opts)

    # Derive new epoch key
    {:ok, new_key} = KeyDerivation.derive_epoch_key(state.conversation_key, new_epoch)

    # Update cache with new key
    new_cache = Map.put(state.key_cache, new_epoch, new_key)

    new_state = %{state | current_epoch: new_epoch, key_cache: new_cache}

    # Purge expired keys
    {:ok, purge_expired_keys(new_state)}
  end

  defp purge_expired_keys(state) do
    oldest = oldest_available_epoch(state)

    new_cache =
      state.key_cache
      |> Enum.filter(fn {epoch_id, _key} -> epoch_id >= oldest end)
      |> Map.new()

    %{state | key_cache: new_cache}
  end

  defp schedule_rotation_check(state) do
    # Cancel existing timer if any
    if state.rotation_timer do
      Process.cancel_timer(state.rotation_timer)
    end

    # Schedule next check
    timer_ref = Process.send_after(self(), :check_rotation, @rotation_check_interval)
    %{state | rotation_timer: timer_ref}
  end
end
