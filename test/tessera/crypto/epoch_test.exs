defmodule Tessera.Crypto.EpochTest do
  use ExUnit.Case, async: true

  alias Tessera.Crypto.Epoch

  describe "duration_to_seconds/1" do
    test "converts :hour to seconds" do
      assert Epoch.duration_to_seconds(:hour) == 3600
    end

    test "converts :day to seconds" do
      assert Epoch.duration_to_seconds(:day) == 86_400
    end

    test "converts :week to seconds" do
      assert Epoch.duration_to_seconds(:week) == 604_800
    end

    test "passes through integer seconds" do
      assert Epoch.duration_to_seconds(7200) == 7200
      assert Epoch.duration_to_seconds(1) == 1
    end
  end

  describe "current_epoch/2" do
    test "returns a non-negative integer" do
      epoch = Epoch.current_epoch(:hour)
      assert is_integer(epoch)
      assert epoch >= 0
    end

    test "returns larger values for shorter durations" do
      hour_epoch = Epoch.current_epoch(:hour)
      day_epoch = Epoch.current_epoch(:day)
      week_epoch = Epoch.current_epoch(:week)

      assert hour_epoch > day_epoch
      assert day_epoch > week_epoch
    end

    test "respects custom epoch_zero" do
      # Use a recent epoch zero
      recent_zero = DateTime.add(DateTime.utc_now(), -3600, :second)

      epoch_default = Epoch.current_epoch(:hour)
      epoch_recent = Epoch.current_epoch(:hour, epoch_zero: recent_zero)

      # Recent epoch zero should produce epoch 1 (we're in the second hour)
      assert epoch_recent < epoch_default
      assert epoch_recent in [0, 1, 2]
    end
  end

  describe "epoch_for_time/3" do
    test "calculates correct epoch for known time" do
      # 24 hours after Unix epoch should be epoch 1 for daily epochs
      time = ~U[1970-01-02 00:00:00Z]
      assert Epoch.epoch_for_time(time, :day) == 1
    end

    test "calculates correct epoch for hourly duration" do
      # 2 hours after Unix epoch
      time = ~U[1970-01-01 02:00:00Z]
      assert Epoch.epoch_for_time(time, :hour) == 2
    end

    test "mid-epoch times return same epoch as start" do
      start_time = ~U[1970-01-01 01:00:00Z]
      mid_time = ~U[1970-01-01 01:30:00Z]
      end_time = ~U[1970-01-01 01:59:59Z]

      assert Epoch.epoch_for_time(start_time, :hour) == 1
      assert Epoch.epoch_for_time(mid_time, :hour) == 1
      assert Epoch.epoch_for_time(end_time, :hour) == 1
    end

    test "epoch boundary transitions correctly" do
      just_before = ~U[1970-01-01 00:59:59Z]
      exactly_at = ~U[1970-01-01 01:00:00Z]
      just_after = ~U[1970-01-01 01:00:01Z]

      assert Epoch.epoch_for_time(just_before, :hour) == 0
      assert Epoch.epoch_for_time(exactly_at, :hour) == 1
      assert Epoch.epoch_for_time(just_after, :hour) == 1
    end

    test "returns 0 for times before epoch_zero" do
      time = ~U[1969-12-31 23:59:59Z]
      assert Epoch.epoch_for_time(time, :hour) == 0
    end

    test "works with custom epoch_zero" do
      epoch_zero = ~U[2024-01-01 00:00:00Z]
      time = ~U[2024-01-01 02:30:00Z]

      assert Epoch.epoch_for_time(time, :hour, epoch_zero: epoch_zero) == 2
    end

    test "works with custom duration in seconds" do
      # 30 minute epochs
      time = ~U[1970-01-01 01:00:00Z]
      assert Epoch.epoch_for_time(time, 1800) == 2
    end
  end

  describe "epoch_bounds/3" do
    test "returns correct bounds for epoch 0" do
      {:ok, start_time, end_time} = Epoch.epoch_bounds(0, :hour)

      assert start_time == ~U[1970-01-01 00:00:00Z]
      assert end_time == ~U[1970-01-01 00:59:59Z]
    end

    test "returns correct bounds for epoch 1" do
      {:ok, start_time, end_time} = Epoch.epoch_bounds(1, :day)

      assert start_time == ~U[1970-01-02 00:00:00Z]
      assert end_time == ~U[1970-01-02 23:59:59Z]
    end

    test "bounds are contiguous" do
      {:ok, _start1, end1} = Epoch.epoch_bounds(5, :hour)
      {:ok, start2, _end2} = Epoch.epoch_bounds(6, :hour)

      # End of epoch 5 + 1 second = start of epoch 6
      assert DateTime.add(end1, 1, :second) == start2
    end

    test "works with custom epoch_zero" do
      epoch_zero = ~U[2024-06-01 00:00:00Z]
      {:ok, start_time, _end_time} = Epoch.epoch_bounds(0, :day, epoch_zero: epoch_zero)

      assert start_time == epoch_zero
    end
  end

  describe "epoch_start/3" do
    test "returns start time of epoch" do
      {:ok, start_time} = Epoch.epoch_start(0, :hour)
      assert start_time == ~U[1970-01-01 00:00:00Z]
    end

    test "returns correct start for later epochs" do
      {:ok, start_time} = Epoch.epoch_start(24, :hour)
      assert start_time == ~U[1970-01-02 00:00:00Z]
    end
  end

  describe "epoch_end/3" do
    test "returns end time of epoch" do
      {:ok, end_time} = Epoch.epoch_end(0, :hour)
      assert end_time == ~U[1970-01-01 00:59:59Z]
    end

    test "end time is 1 second before next epoch start" do
      {:ok, end_time} = Epoch.epoch_end(5, :hour)
      {:ok, next_start} = Epoch.epoch_start(6, :hour)

      assert DateTime.add(end_time, 1, :second) == next_start
    end
  end

  describe "time_in_epoch?/4" do
    test "returns true for time within epoch" do
      time = ~U[1970-01-01 00:30:00Z]
      assert Epoch.time_in_epoch?(time, 0, :hour) == true
    end

    test "returns false for time outside epoch" do
      time = ~U[1970-01-01 01:30:00Z]
      assert Epoch.time_in_epoch?(time, 0, :hour) == false
    end

    test "returns true for exact epoch start" do
      time = ~U[1970-01-01 01:00:00Z]
      assert Epoch.time_in_epoch?(time, 1, :hour) == true
    end

    test "returns true for just before epoch end" do
      time = ~U[1970-01-01 00:59:59Z]
      assert Epoch.time_in_epoch?(time, 0, :hour) == true
    end
  end

  describe "time_until_rotation/2" do
    test "returns positive integer" do
      seconds = Epoch.time_until_rotation(:hour)
      assert is_integer(seconds)
      assert seconds >= 0
    end

    test "returns value less than or equal to duration" do
      seconds = Epoch.time_until_rotation(:hour)
      assert seconds <= 3600
    end

    test "shorter durations have less max time" do
      hour_max = Epoch.time_until_rotation(:hour)
      day_max = Epoch.time_until_rotation(:day)

      # Both should be <= their respective durations
      assert hour_max <= 3600
      assert day_max <= 86_400
    end
  end

  describe "epochs_in_range/4" do
    test "returns single epoch for time within one epoch" do
      start_time = ~U[1970-01-01 00:15:00Z]
      end_time = ~U[1970-01-01 00:45:00Z]

      epochs = Epoch.epochs_in_range(start_time, end_time, :hour)
      assert epochs == [0]
    end

    test "returns multiple epochs for spanning time range" do
      start_time = ~U[1970-01-01 00:00:00Z]
      end_time = ~U[1970-01-01 02:30:00Z]

      epochs = Epoch.epochs_in_range(start_time, end_time, :hour)
      assert epochs == [0, 1, 2]
    end

    test "includes both boundary epochs" do
      start_time = ~U[1970-01-01 00:59:59Z]
      end_time = ~U[1970-01-01 01:00:01Z]

      epochs = Epoch.epochs_in_range(start_time, end_time, :hour)
      assert epochs == [0, 1]
    end

    test "works with daily epochs" do
      start_time = ~U[1970-01-01 12:00:00Z]
      end_time = ~U[1970-01-03 12:00:00Z]

      epochs = Epoch.epochs_in_range(start_time, end_time, :day)
      assert epochs == [0, 1, 2]
    end
  end

  describe "valid_epoch_id?/1" do
    test "returns true for non-negative integers" do
      assert Epoch.valid_epoch_id?(0) == true
      assert Epoch.valid_epoch_id?(1) == true
      assert Epoch.valid_epoch_id?(999_999) == true
    end

    test "returns false for negative integers" do
      assert Epoch.valid_epoch_id?(-1) == false
      assert Epoch.valid_epoch_id?(-100) == false
    end

    test "returns false for non-integers" do
      assert Epoch.valid_epoch_id?(1.5) == false
      assert Epoch.valid_epoch_id?("1") == false
      assert Epoch.valid_epoch_id?(nil) == false
    end
  end

  describe "next_epoch/1" do
    test "returns next sequential epoch" do
      assert Epoch.next_epoch(0) == 1
      assert Epoch.next_epoch(42) == 43
      assert Epoch.next_epoch(999) == 1000
    end
  end

  describe "previous_epoch/1" do
    test "returns previous sequential epoch" do
      assert Epoch.previous_epoch(1) == 0
      assert Epoch.previous_epoch(42) == 41
      assert Epoch.previous_epoch(1000) == 999
    end

    test "returns 0 when already at epoch 0" do
      assert Epoch.previous_epoch(0) == 0
    end
  end

  describe "consistency properties" do
    test "epoch_for_time is consistent with epoch_bounds" do
      # For any epoch, a time within its bounds should return that epoch
      for epoch_id <- [0, 1, 10, 100] do
        {:ok, start_time, end_time} = Epoch.epoch_bounds(epoch_id, :hour)
        mid_time = DateTime.add(start_time, 1800, :second)

        assert Epoch.epoch_for_time(start_time, :hour) == epoch_id
        assert Epoch.epoch_for_time(mid_time, :hour) == epoch_id
        assert Epoch.epoch_for_time(end_time, :hour) == epoch_id
      end
    end

    test "current_epoch matches epoch_for_time(now)" do
      now = DateTime.utc_now()
      current = Epoch.current_epoch(:hour)
      calculated = Epoch.epoch_for_time(now, :hour)

      assert current == calculated
    end
  end
end
