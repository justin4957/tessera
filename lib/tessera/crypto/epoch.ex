defmodule Tessera.Crypto.Epoch do
  @moduledoc """
  Epoch calculation and time-based key rotation.

  Epochs are discrete time periods used to partition cryptographic keys.
  Each epoch has a unique epoch number that can be used to derive
  time-bounded keys via the `KeyDerivation` module.

  ## Epoch Duration

  Epochs can be configured with different durations:
  - `:hour` - 1 hour epochs (high security, more rotation)
  - `:day` - 24 hour epochs (balanced)
  - `:week` - 7 day epochs (less rotation overhead)
  - Custom duration in seconds

  ## Time Reference

  Epochs are calculated from a configurable reference point (epoch zero).
  By default, this is the Unix epoch (1970-01-01 00:00:00 UTC).

  ## Usage

      # Get current epoch number
      Epoch.current_epoch(:hour)
      # => 482_345

      # Get epoch for a specific time
      Epoch.epoch_for_time(~U[2024-06-15 14:30:00Z], :day)
      # => 19_889

      # Get time bounds for an epoch
      {:ok, start_time, end_time} = Epoch.epoch_bounds(100, :day)

      # Check if a time falls within an epoch
      Epoch.time_in_epoch?(~U[2024-06-15 14:30:00Z], 19_889, :day)
      # => true
  """

  @type epoch_id :: non_neg_integer()
  @type duration :: :hour | :day | :week | pos_integer()

  # Duration in seconds
  @duration_hour 3600
  @duration_day 86_400
  @duration_week 604_800

  # Default epoch zero: Unix epoch
  @default_epoch_zero ~U[1970-01-01 00:00:00Z]

  @doc """
  Returns the current epoch number for the given duration.

  ## Examples

      Epoch.current_epoch(:hour)
      Epoch.current_epoch(:day)
      Epoch.current_epoch(3600)  # Custom: 1 hour in seconds
  """
  @spec current_epoch(duration(), keyword()) :: epoch_id()
  def current_epoch(duration, opts \\ []) do
    epoch_for_time(DateTime.utc_now(), duration, opts)
  end

  @doc """
  Returns the epoch number for a given timestamp.

  ## Options

  - `:epoch_zero` - Reference point for epoch 0 (default: Unix epoch)

  ## Examples

      Epoch.epoch_for_time(~U[2024-06-15 14:30:00Z], :day)
      # => 19_889
  """
  @spec epoch_for_time(DateTime.t(), duration(), keyword()) :: epoch_id()
  def epoch_for_time(%DateTime{} = time, duration, opts \\ []) do
    epoch_zero = Keyword.get(opts, :epoch_zero, @default_epoch_zero)
    duration_seconds = duration_to_seconds(duration)

    seconds_since_zero = DateTime.diff(time, epoch_zero, :second)

    if seconds_since_zero < 0 do
      # Time is before epoch zero
      0
    else
      div(seconds_since_zero, duration_seconds)
    end
  end

  @doc """
  Returns the start and end times for a given epoch.

  ## Examples

      {:ok, start_time, end_time} = Epoch.epoch_bounds(100, :day)
  """
  @spec epoch_bounds(epoch_id(), duration(), keyword()) ::
          {:ok, DateTime.t(), DateTime.t()} | {:error, term()}
  def epoch_bounds(epoch_id, duration, opts \\ []) when epoch_id >= 0 do
    epoch_zero = Keyword.get(opts, :epoch_zero, @default_epoch_zero)
    duration_seconds = duration_to_seconds(duration)

    start_offset = epoch_id * duration_seconds
    end_offset = (epoch_id + 1) * duration_seconds - 1

    start_time = DateTime.add(epoch_zero, start_offset, :second)
    end_time = DateTime.add(epoch_zero, end_offset, :second)

    {:ok, start_time, end_time}
  end

  @doc """
  Returns the start time of a given epoch.

  ## Examples

      {:ok, start_time} = Epoch.epoch_start(100, :day)
  """
  @spec epoch_start(epoch_id(), duration(), keyword()) :: {:ok, DateTime.t()}
  def epoch_start(epoch_id, duration, opts \\ []) when epoch_id >= 0 do
    epoch_zero = Keyword.get(opts, :epoch_zero, @default_epoch_zero)
    duration_seconds = duration_to_seconds(duration)

    offset = epoch_id * duration_seconds
    {:ok, DateTime.add(epoch_zero, offset, :second)}
  end

  @doc """
  Returns the end time of a given epoch.

  ## Examples

      {:ok, end_time} = Epoch.epoch_end(100, :day)
  """
  @spec epoch_end(epoch_id(), duration(), keyword()) :: {:ok, DateTime.t()}
  def epoch_end(epoch_id, duration, opts \\ []) when epoch_id >= 0 do
    epoch_zero = Keyword.get(opts, :epoch_zero, @default_epoch_zero)
    duration_seconds = duration_to_seconds(duration)

    offset = (epoch_id + 1) * duration_seconds - 1
    {:ok, DateTime.add(epoch_zero, offset, :second)}
  end

  @doc """
  Checks if a timestamp falls within a given epoch.

  ## Examples

      Epoch.time_in_epoch?(~U[2024-06-15 14:30:00Z], 19_889, :day)
      # => true
  """
  @spec time_in_epoch?(DateTime.t(), epoch_id(), duration(), keyword()) :: boolean()
  def time_in_epoch?(%DateTime{} = time, epoch_id, duration, opts \\ []) do
    epoch_for_time(time, duration, opts) == epoch_id
  end

  @doc """
  Returns the time remaining in the current epoch.

  ## Examples

      Epoch.time_until_rotation(:hour)
      # => 1847  # seconds until next epoch
  """
  @spec time_until_rotation(duration(), keyword()) :: non_neg_integer()
  def time_until_rotation(duration, opts \\ []) do
    now = DateTime.utc_now()
    current = current_epoch(duration, opts)
    {:ok, _start, end_time} = epoch_bounds(current, duration, opts)

    max(0, DateTime.diff(end_time, now, :second) + 1)
  end

  @doc """
  Returns a list of epoch IDs within a time range.

  ## Examples

      Epoch.epochs_in_range(~U[2024-06-01 00:00:00Z], ~U[2024-06-03 00:00:00Z], :day)
      # => [19_875, 19_876, 19_877]
  """
  @spec epochs_in_range(DateTime.t(), DateTime.t(), duration(), keyword()) :: [epoch_id()]
  def epochs_in_range(%DateTime{} = start_time, %DateTime{} = end_time, duration, opts \\ []) do
    start_epoch = epoch_for_time(start_time, duration, opts)
    end_epoch = epoch_for_time(end_time, duration, opts)

    Enum.to_list(start_epoch..end_epoch)
  end

  @doc """
  Returns the duration in seconds for a given duration type.

  ## Examples

      Epoch.duration_to_seconds(:hour)
      # => 3600

      Epoch.duration_to_seconds(:day)
      # => 86400
  """
  @spec duration_to_seconds(duration()) :: pos_integer()
  def duration_to_seconds(:hour), do: @duration_hour
  def duration_to_seconds(:day), do: @duration_day
  def duration_to_seconds(:week), do: @duration_week
  def duration_to_seconds(seconds) when is_integer(seconds) and seconds > 0, do: seconds

  @doc """
  Validates that an epoch ID is valid (non-negative integer).
  """
  @spec valid_epoch_id?(term()) :: boolean()
  def valid_epoch_id?(epoch_id) when is_integer(epoch_id) and epoch_id >= 0, do: true
  def valid_epoch_id?(_), do: false

  @doc """
  Returns the next epoch ID after the given one.
  """
  @spec next_epoch(epoch_id()) :: epoch_id()
  def next_epoch(epoch_id) when is_integer(epoch_id) and epoch_id >= 0 do
    epoch_id + 1
  end

  @doc """
  Returns the previous epoch ID, or 0 if already at epoch 0.
  """
  @spec previous_epoch(epoch_id()) :: epoch_id()
  def previous_epoch(0), do: 0
  def previous_epoch(epoch_id) when is_integer(epoch_id) and epoch_id > 0, do: epoch_id - 1
end
