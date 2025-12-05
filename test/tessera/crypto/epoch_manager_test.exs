defmodule Tessera.Crypto.EpochManagerTest do
  use ExUnit.Case, async: false

  alias Tessera.Crypto.{Epoch, EpochManager, KeyDerivation}
  alias Tessera.Crypto.Keys.EpochKey

  setup do
    # Create a conversation key for testing
    {:ok, root_key} = KeyDerivation.generate_root_key()
    {:ok, conv_key} = KeyDerivation.derive_conversation_key(root_key, "test-conversation")

    {:ok, conv_key: conv_key, root_key: root_key}
  end

  describe "start_link/1" do
    test "starts with required options", %{conv_key: conv_key} do
      {:ok, pid} =
        EpochManager.start_link(
          name: :test_epoch_manager_start,
          conversation_key: conv_key
        )

      assert Process.alive?(pid)
      EpochManager.stop(:test_epoch_manager_start)
    end

    test "starts with all options", %{conv_key: conv_key} do
      {:ok, pid} =
        EpochManager.start_link(
          name: :test_epoch_manager_full,
          conversation_key: conv_key,
          duration: :day,
          retention_epochs: 30,
          epoch_zero: ~U[2024-01-01 00:00:00Z],
          auto_rotate: false
        )

      assert Process.alive?(pid)
      EpochManager.stop(:test_epoch_manager_full)
    end

    test "fails without conversation_key" do
      # Trap exits so the test doesn't crash
      Process.flag(:trap_exit, true)

      # This will fail because conversation_key is required
      result = EpochManager.start_link(name: :test_fail_no_key)

      # The call should return an error or we should receive an EXIT
      case result do
        {:error, _} ->
          assert true

        {:ok, pid} ->
          # Should not happen, but cleanup if it does
          EpochManager.stop(pid)
          flunk("Expected start_link to fail without conversation_key")
      end
    end
  end

  describe "current_key/1" do
    setup %{conv_key: conv_key} do
      {:ok, _pid} =
        EpochManager.start_link(
          name: :test_current_key,
          conversation_key: conv_key,
          duration: :hour,
          auto_rotate: false
        )

      on_exit(fn ->
        catch_exit(EpochManager.stop(:test_current_key))
      end)

      :ok
    end

    test "returns an epoch key" do
      {:ok, %EpochKey{} = key} = EpochManager.current_key(:test_current_key)
      assert byte_size(key.material) == 32
    end

    test "returns same key on repeated calls" do
      {:ok, key1} = EpochManager.current_key(:test_current_key)
      {:ok, key2} = EpochManager.current_key(:test_current_key)

      assert KeyDerivation.equal?(key1, key2)
    end

    test "key matches current epoch" do
      {:ok, key} = EpochManager.current_key(:test_current_key)
      current_epoch = EpochManager.current_epoch(:test_current_key)

      assert key.epoch_number == current_epoch
    end
  end

  describe "current_epoch/1" do
    setup %{conv_key: conv_key} do
      {:ok, _pid} =
        EpochManager.start_link(
          name: :test_current_epoch,
          conversation_key: conv_key,
          duration: :hour,
          auto_rotate: false
        )

      on_exit(fn ->
        catch_exit(EpochManager.stop(:test_current_epoch))
      end)

      :ok
    end

    test "returns current epoch number" do
      epoch = EpochManager.current_epoch(:test_current_epoch)
      assert is_integer(epoch)
      assert epoch >= 0
    end

    test "matches Epoch.current_epoch calculation" do
      epoch = EpochManager.current_epoch(:test_current_epoch)
      calculated = Epoch.current_epoch(:hour)

      assert epoch == calculated
    end
  end

  describe "get_key/2" do
    setup %{conv_key: conv_key} do
      {:ok, _pid} =
        EpochManager.start_link(
          name: :test_get_key,
          conversation_key: conv_key,
          duration: :hour,
          retention_epochs: 10,
          auto_rotate: false
        )

      on_exit(fn ->
        catch_exit(EpochManager.stop(:test_get_key))
      end)

      :ok
    end

    test "returns current epoch key" do
      current = EpochManager.current_epoch(:test_get_key)
      {:ok, key} = EpochManager.get_key(current, :test_get_key)

      assert key.epoch_number == current
    end

    test "returns error for future epoch" do
      current = EpochManager.current_epoch(:test_get_key)
      future = current + 100

      assert {:error, :future_epoch} = EpochManager.get_key(future, :test_get_key)
    end

    test "returns error for expired epoch" do
      current = EpochManager.current_epoch(:test_get_key)
      # Way before retention window
      expired = max(0, current - 1000)

      if expired < current - 10 do
        assert {:error, :expired} = EpochManager.get_key(expired, :test_get_key)
      end
    end

    test "returns error for invalid epoch" do
      assert {:error, :invalid_epoch} = EpochManager.get_key(-1, :test_get_key)
    end

    test "derives keys within retention window", %{conv_key: conv_key} do
      current = EpochManager.current_epoch(:test_get_key)

      # Get a key within retention that wasn't pre-cached
      within_retention = max(0, current - 5)

      {:ok, key} = EpochManager.get_key(within_retention, :test_get_key)

      # Verify it matches direct derivation
      {:ok, expected} = KeyDerivation.derive_epoch_key(conv_key, within_retention)
      assert KeyDerivation.equal?(key, expected)
    end
  end

  describe "key_for_time/2" do
    setup %{conv_key: conv_key} do
      {:ok, _pid} =
        EpochManager.start_link(
          name: :test_key_for_time,
          conversation_key: conv_key,
          duration: :hour,
          retention_epochs: 24,
          auto_rotate: false
        )

      on_exit(fn ->
        catch_exit(EpochManager.stop(:test_key_for_time))
      end)

      :ok
    end

    test "returns key for current time" do
      now = DateTime.utc_now()
      {:ok, key} = EpochManager.key_for_time(now, :test_key_for_time)

      assert %EpochKey{} = key
    end

    test "returns correct epoch for specific time" do
      # Get key for a time 2 hours ago
      two_hours_ago = DateTime.add(DateTime.utc_now(), -7200, :second)
      {:ok, key} = EpochManager.key_for_time(two_hours_ago, :test_key_for_time)

      expected_epoch = Epoch.epoch_for_time(two_hours_ago, :hour)
      assert key.epoch_number == expected_epoch
    end

    test "returns error for future time" do
      future = DateTime.add(DateTime.utc_now(), 7200, :second)
      assert {:error, :future_epoch} = EpochManager.key_for_time(future, :test_key_for_time)
    end
  end

  describe "rotate_now/1" do
    setup %{conv_key: conv_key} do
      {:ok, _pid} =
        EpochManager.start_link(
          name: :test_rotate_now,
          conversation_key: conv_key,
          duration: :hour,
          auto_rotate: false
        )

      on_exit(fn ->
        catch_exit(EpochManager.stop(:test_rotate_now))
      end)

      :ok
    end

    test "returns current epoch after rotation" do
      {:ok, epoch} = EpochManager.rotate_now(:test_rotate_now)
      expected = Epoch.current_epoch(:hour)

      assert epoch == expected
    end

    test "updates current key" do
      {:ok, key_before} = EpochManager.current_key(:test_rotate_now)
      {:ok, _epoch} = EpochManager.rotate_now(:test_rotate_now)
      {:ok, key_after} = EpochManager.current_key(:test_rotate_now)

      # Keys should be equal since we're in the same epoch
      # (rotate_now syncs to current calculated epoch)
      assert KeyDerivation.equal?(key_before, key_after)
    end
  end

  describe "info/1" do
    setup %{conv_key: conv_key} do
      {:ok, _pid} =
        EpochManager.start_link(
          name: :test_info,
          conversation_key: conv_key,
          duration: :day,
          retention_epochs: 7,
          auto_rotate: false
        )

      on_exit(fn ->
        catch_exit(EpochManager.stop(:test_info))
      end)

      :ok
    end

    test "returns manager information" do
      info = EpochManager.info(:test_info)

      assert is_map(info)
      assert is_integer(info.current_epoch)
      assert info.duration == :day
      assert info.retention_epochs == 7
      assert is_list(info.cached_epochs)
      assert is_integer(info.oldest_available)
      assert is_integer(info.time_until_rotation)
    end

    test "cached_epochs includes current epoch" do
      info = EpochManager.info(:test_info)
      assert info.current_epoch in info.cached_epochs
    end

    test "time_until_rotation is reasonable" do
      info = EpochManager.info(:test_info)
      # Should be between 0 and duration (86400 for day)
      assert info.time_until_rotation >= 0
      assert info.time_until_rotation <= 86_400
    end
  end

  describe "available_epochs/1" do
    setup %{conv_key: conv_key} do
      {:ok, _pid} =
        EpochManager.start_link(
          name: :test_available,
          conversation_key: conv_key,
          duration: :hour,
          retention_epochs: 5,
          auto_rotate: false
        )

      on_exit(fn ->
        catch_exit(EpochManager.stop(:test_available))
      end)

      :ok
    end

    test "returns list of cached epochs" do
      epochs = EpochManager.available_epochs(:test_available)
      assert is_list(epochs)
      assert length(epochs) >= 1
    end

    test "list is sorted" do
      epochs = EpochManager.available_epochs(:test_available)
      assert epochs == Enum.sort(epochs)
    end
  end

  describe "purge_expired/1" do
    setup %{conv_key: conv_key} do
      {:ok, _pid} =
        EpochManager.start_link(
          name: :test_purge,
          conversation_key: conv_key,
          duration: :hour,
          retention_epochs: 3,
          auto_rotate: false
        )

      on_exit(fn ->
        catch_exit(EpochManager.stop(:test_purge))
      end)

      :ok
    end

    test "completes without error" do
      assert :ok = EpochManager.purge_expired(:test_purge)
    end
  end

  describe "key derivation consistency" do
    setup %{conv_key: conv_key} do
      {:ok, _pid} =
        EpochManager.start_link(
          name: :test_consistency,
          conversation_key: conv_key,
          duration: :hour,
          auto_rotate: false
        )

      on_exit(fn ->
        catch_exit(EpochManager.stop(:test_consistency))
      end)

      {:ok, conv_key: conv_key}
    end

    test "manager keys match direct derivation", %{conv_key: conv_key} do
      current = EpochManager.current_epoch(:test_consistency)
      {:ok, manager_key} = EpochManager.get_key(current, :test_consistency)
      {:ok, direct_key} = KeyDerivation.derive_epoch_key(conv_key, current)

      assert KeyDerivation.equal?(manager_key, direct_key)
    end

    test "keys for past epochs match direct derivation", %{conv_key: conv_key} do
      current = EpochManager.current_epoch(:test_consistency)

      for offset <- 1..5 do
        epoch = max(0, current - offset)
        {:ok, manager_key} = EpochManager.get_key(epoch, :test_consistency)
        {:ok, direct_key} = KeyDerivation.derive_epoch_key(conv_key, epoch)

        assert KeyDerivation.equal?(manager_key, direct_key),
               "Keys don't match for epoch #{epoch}"
      end
    end
  end

  describe "custom epoch_zero" do
    setup %{conv_key: conv_key} do
      epoch_zero = ~U[2024-01-01 00:00:00Z]

      {:ok, _pid} =
        EpochManager.start_link(
          name: :test_custom_zero,
          conversation_key: conv_key,
          duration: :hour,
          epoch_zero: epoch_zero,
          auto_rotate: false
        )

      on_exit(fn ->
        catch_exit(EpochManager.stop(:test_custom_zero))
      end)

      {:ok, epoch_zero: epoch_zero}
    end

    test "uses custom epoch_zero for calculations", %{epoch_zero: epoch_zero} do
      current = EpochManager.current_epoch(:test_custom_zero)
      expected = Epoch.current_epoch(:hour, epoch_zero: epoch_zero)

      assert current == expected
    end

    test "key_for_time respects custom epoch_zero" do
      # Get current time and calculate what epoch it should be
      now = DateTime.utc_now()
      {:ok, key} = EpochManager.key_for_time(now, :test_custom_zero)

      # The key's epoch should match what Epoch calculates with the custom zero
      current = EpochManager.current_epoch(:test_custom_zero)
      assert key.epoch_number == current
    end
  end

  describe "auto_rotate disabled" do
    setup %{conv_key: conv_key} do
      {:ok, pid} =
        EpochManager.start_link(
          name: :test_no_auto_rotate,
          conversation_key: conv_key,
          duration: :hour,
          auto_rotate: false
        )

      on_exit(fn ->
        catch_exit(EpochManager.stop(:test_no_auto_rotate))
      end)

      {:ok, pid: pid}
    end

    test "process stays alive", %{pid: pid} do
      # Give it a moment
      Process.sleep(100)
      assert Process.alive?(pid)
    end
  end

  describe "retention policy" do
    test "oldest_available respects retention", %{conv_key: conv_key} do
      {:ok, _pid} =
        EpochManager.start_link(
          name: :test_retention_oldest,
          conversation_key: conv_key,
          duration: :hour,
          retention_epochs: 5,
          auto_rotate: false
        )

      on_exit(fn ->
        catch_exit(EpochManager.stop(:test_retention_oldest))
      end)

      info = EpochManager.info(:test_retention_oldest)
      current = info.current_epoch

      # Oldest should be at most (current - retention + 1)
      expected_oldest = max(0, current - 5 + 1)
      assert info.oldest_available == expected_oldest
    end

    test "expired epochs return error", %{conv_key: conv_key} do
      {:ok, _pid} =
        EpochManager.start_link(
          name: :test_retention_expired,
          conversation_key: conv_key,
          duration: :hour,
          retention_epochs: 3,
          auto_rotate: false
        )

      on_exit(fn ->
        catch_exit(EpochManager.stop(:test_retention_expired))
      end)

      current = EpochManager.current_epoch(:test_retention_expired)

      # Try to get an epoch well outside retention
      if current > 100 do
        assert {:error, :expired} =
                 EpochManager.get_key(current - 100, :test_retention_expired)
      end
    end
  end
end
