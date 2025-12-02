defmodule Tessera.Core.Rights.TemporalInterval do
  @moduledoc """
  Represents a time interval for temporal access rights.

  Intervals can be:
  - Bounded: both start and end times specified
  - Open-ended: only start time (grants that haven't been revoked)
  - Instantaneous: single point in time

  ## Examples

      # Access from Jan 1 to Mar 31, 2024
      interval = TemporalInterval.new(~U[2024-01-01 00:00:00Z], ~U[2024-03-31 23:59:59Z])

      # Open-ended access starting now
      interval = TemporalInterval.from_now()

      # Check if a point in time falls within the interval
      TemporalInterval.contains?(interval, DateTime.utc_now())
  """

  @enforce_keys [:start_time]
  defstruct [:start_time, :end_time]

  @type t :: %__MODULE__{
          start_time: DateTime.t(),
          end_time: DateTime.t() | nil
        }

  @doc """
  Creates a new temporal interval.
  """
  @spec new(DateTime.t(), DateTime.t() | nil) :: t()
  def new(start_time, end_time \\ nil) do
    %__MODULE__{start_time: start_time, end_time: end_time}
  end

  @doc """
  Creates an interval starting from the current time with no end.
  """
  @spec from_now() :: t()
  def from_now do
    new(DateTime.utc_now(), nil)
  end

  @doc """
  Creates an interval starting now with a specific duration.
  """
  @spec for_duration(integer(), :second | :minute | :hour | :day) :: t()
  def for_duration(amount, unit) do
    start_time = DateTime.utc_now()
    end_time = DateTime.add(start_time, duration_to_seconds(amount, unit), :second)
    new(start_time, end_time)
  end

  @doc """
  Checks if a given datetime falls within the interval.
  """
  @spec contains?(t(), DateTime.t()) :: boolean()
  def contains?(%__MODULE__{start_time: start_time, end_time: nil}, datetime) do
    DateTime.compare(datetime, start_time) in [:gt, :eq]
  end

  def contains?(%__MODULE__{start_time: start_time, end_time: end_time}, datetime) do
    DateTime.compare(datetime, start_time) in [:gt, :eq] and
      DateTime.compare(datetime, end_time) in [:lt, :eq]
  end

  @doc """
  Checks if two intervals overlap.
  """
  @spec overlaps?(t(), t()) :: boolean()
  def overlaps?(interval_a, interval_b) do
    starts_before_other_ends?(interval_a, interval_b) and
      starts_before_other_ends?(interval_b, interval_a)
  end

  @doc """
  Extends an interval to a new end time.
  Returns error if new end time is before current end time.
  """
  @spec extend(t(), DateTime.t()) :: {:ok, t()} | {:error, :invalid_extension}
  def extend(%__MODULE__{end_time: nil} = interval, new_end_time) do
    {:ok, %{interval | end_time: new_end_time}}
  end

  def extend(%__MODULE__{end_time: current_end} = interval, new_end_time) do
    if DateTime.compare(new_end_time, current_end) == :gt do
      {:ok, %{interval | end_time: new_end_time}}
    else
      {:error, :invalid_extension}
    end
  end

  @doc """
  Truncates an interval at a specific point (for revocation).
  """
  @spec truncate_at(t(), DateTime.t()) :: {:ok, t()} | {:error, :before_start}
  def truncate_at(%__MODULE__{start_time: start_time} = interval, revoke_time) do
    if DateTime.compare(revoke_time, start_time) == :lt do
      {:error, :before_start}
    else
      {:ok, %{interval | end_time: revoke_time}}
    end
  end

  @doc """
  Returns a slice of the interval (intersection with another interval).
  """
  @spec slice(t(), t()) :: {:ok, t()} | {:error, :no_overlap}
  def slice(interval_a, interval_b) do
    if overlaps?(interval_a, interval_b) do
      new_start = max_datetime(interval_a.start_time, interval_b.start_time)
      new_end = min_end_time(interval_a.end_time, interval_b.end_time)
      {:ok, new(new_start, new_end)}
    else
      {:error, :no_overlap}
    end
  end

  @doc """
  Checks if the interval is currently active (now falls within it).
  """
  @spec active?(t()) :: boolean()
  def active?(interval) do
    contains?(interval, DateTime.utc_now())
  end

  @doc """
  Checks if the interval has expired.
  """
  @spec expired?(t()) :: boolean()
  def expired?(%__MODULE__{end_time: nil}), do: false

  def expired?(%__MODULE__{end_time: end_time}) do
    DateTime.compare(DateTime.utc_now(), end_time) == :gt
  end

  # Private helpers

  defp duration_to_seconds(amount, :second), do: amount
  defp duration_to_seconds(amount, :minute), do: amount * 60
  defp duration_to_seconds(amount, :hour), do: amount * 3600
  defp duration_to_seconds(amount, :day), do: amount * 86400

  defp starts_before_other_ends?(%__MODULE__{start_time: _start}, %__MODULE__{end_time: nil}) do
    true
  end

  defp starts_before_other_ends?(%__MODULE__{start_time: start}, %__MODULE__{end_time: end_time}) do
    DateTime.compare(start, end_time) in [:lt, :eq]
  end

  defp max_datetime(a, b) do
    if DateTime.compare(a, b) == :gt, do: a, else: b
  end

  defp min_end_time(nil, b), do: b
  defp min_end_time(a, nil), do: a

  defp min_end_time(a, b) do
    if DateTime.compare(a, b) == :lt, do: a, else: b
  end
end
