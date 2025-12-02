defmodule Tessera.Core.Rights.TemporalIntervalTest do
  use ExUnit.Case

  alias Tessera.Core.Rights.TemporalInterval

  describe "new/2" do
    test "creates bounded interval" do
      start_time = ~U[2024-01-01 00:00:00Z]
      end_time = ~U[2024-03-31 23:59:59Z]

      interval = TemporalInterval.new(start_time, end_time)

      assert interval.start_time == start_time
      assert interval.end_time == end_time
    end

    test "creates open-ended interval" do
      start_time = ~U[2024-01-01 00:00:00Z]

      interval = TemporalInterval.new(start_time)

      assert interval.start_time == start_time
      assert interval.end_time == nil
    end
  end

  describe "for_duration/2" do
    test "creates interval with specified duration" do
      interval = TemporalInterval.for_duration(1, :hour)

      assert interval.start_time != nil
      assert interval.end_time != nil

      diff = DateTime.diff(interval.end_time, interval.start_time, :second)
      assert diff == 3600
    end
  end

  describe "contains?/2" do
    test "returns true when datetime is within bounded interval" do
      interval = TemporalInterval.new(~U[2024-01-01 00:00:00Z], ~U[2024-12-31 23:59:59Z])

      assert TemporalInterval.contains?(interval, ~U[2024-06-15 12:00:00Z])
    end

    test "returns false when datetime is outside bounded interval" do
      interval = TemporalInterval.new(~U[2024-01-01 00:00:00Z], ~U[2024-12-31 23:59:59Z])

      refute TemporalInterval.contains?(interval, ~U[2025-01-01 00:00:00Z])
    end

    test "returns true when datetime is after start of open-ended interval" do
      interval = TemporalInterval.new(~U[2024-01-01 00:00:00Z])

      assert TemporalInterval.contains?(interval, ~U[2099-12-31 23:59:59Z])
    end
  end

  describe "overlaps?/2" do
    test "returns true for overlapping intervals" do
      interval_a = TemporalInterval.new(~U[2024-01-01 00:00:00Z], ~U[2024-06-30 23:59:59Z])
      interval_b = TemporalInterval.new(~U[2024-04-01 00:00:00Z], ~U[2024-12-31 23:59:59Z])

      assert TemporalInterval.overlaps?(interval_a, interval_b)
    end

    test "returns false for non-overlapping intervals" do
      interval_a = TemporalInterval.new(~U[2024-01-01 00:00:00Z], ~U[2024-03-31 23:59:59Z])
      interval_b = TemporalInterval.new(~U[2024-07-01 00:00:00Z], ~U[2024-12-31 23:59:59Z])

      refute TemporalInterval.overlaps?(interval_a, interval_b)
    end
  end

  describe "extend/2" do
    test "extends interval to new end time" do
      interval = TemporalInterval.new(~U[2024-01-01 00:00:00Z], ~U[2024-06-30 23:59:59Z])
      new_end = ~U[2024-12-31 23:59:59Z]

      {:ok, extended} = TemporalInterval.extend(interval, new_end)

      assert extended.end_time == new_end
    end

    test "returns error when new end is before current end" do
      interval = TemporalInterval.new(~U[2024-01-01 00:00:00Z], ~U[2024-12-31 23:59:59Z])
      new_end = ~U[2024-06-30 23:59:59Z]

      assert {:error, :invalid_extension} = TemporalInterval.extend(interval, new_end)
    end
  end

  describe "truncate_at/2" do
    test "truncates interval at specified time" do
      interval = TemporalInterval.new(~U[2024-01-01 00:00:00Z], ~U[2024-12-31 23:59:59Z])
      revoke_time = ~U[2024-06-15 12:00:00Z]

      {:ok, truncated} = TemporalInterval.truncate_at(interval, revoke_time)

      assert truncated.end_time == revoke_time
    end

    test "returns error when truncate time is before start" do
      interval = TemporalInterval.new(~U[2024-06-01 00:00:00Z], ~U[2024-12-31 23:59:59Z])
      revoke_time = ~U[2024-01-01 00:00:00Z]

      assert {:error, :before_start} = TemporalInterval.truncate_at(interval, revoke_time)
    end
  end

  describe "slice/2" do
    test "returns intersection of overlapping intervals" do
      interval_a = TemporalInterval.new(~U[2024-01-01 00:00:00Z], ~U[2024-12-31 23:59:59Z])
      interval_b = TemporalInterval.new(~U[2024-04-01 00:00:00Z], ~U[2024-06-30 23:59:59Z])

      {:ok, sliced} = TemporalInterval.slice(interval_a, interval_b)

      assert sliced.start_time == ~U[2024-04-01 00:00:00Z]
      assert sliced.end_time == ~U[2024-06-30 23:59:59Z]
    end

    test "returns error for non-overlapping intervals" do
      interval_a = TemporalInterval.new(~U[2024-01-01 00:00:00Z], ~U[2024-03-31 23:59:59Z])
      interval_b = TemporalInterval.new(~U[2024-07-01 00:00:00Z], ~U[2024-12-31 23:59:59Z])

      assert {:error, :no_overlap} = TemporalInterval.slice(interval_a, interval_b)
    end
  end
end
