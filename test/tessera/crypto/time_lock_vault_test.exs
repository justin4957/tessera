defmodule Tessera.Crypto.TimeLockVaultTest do
  use ExUnit.Case, async: false

  alias Tessera.Crypto.{KeyDerivation, TimeLockVault}
  alias Tessera.Core.Rights.TemporalInterval

  setup do
    {:ok, root_key} = KeyDerivation.generate_root_key()
    {:ok, conv_key} = KeyDerivation.derive_conversation_key(root_key, "test-vault")

    {:ok, conv_key: conv_key}
  end

  describe "start_link/1" do
    test "starts vault successfully", %{conv_key: conv_key} do
      {:ok, pid} =
        TimeLockVault.start_link(
          name: :test_vault_start,
          conversation_key: conv_key
        )

      assert Process.alive?(pid)
      TimeLockVault.stop(:test_vault_start)
    end

    test "starts with custom options", %{conv_key: conv_key} do
      {:ok, pid} =
        TimeLockVault.start_link(
          name: :test_vault_custom,
          conversation_key: conv_key,
          duration: :day,
          retention_epochs: 30
        )

      assert Process.alive?(pid)
      TimeLockVault.stop(:test_vault_custom)
    end
  end

  describe "seal_until/4 and unseal/2" do
    setup %{conv_key: conv_key} do
      {:ok, _pid} =
        TimeLockVault.start_link(
          name: :test_seal_until,
          conversation_key: conv_key,
          duration: :hour
        )

      on_exit(fn ->
        catch_exit(TimeLockVault.stop(:test_seal_until))
      end)

      :ok
    end

    test "seals and unseals data before deadline" do
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      {:ok, sealed} = TimeLockVault.seal_until(:test_seal_until, "secret data", deadline)
      assert is_binary(sealed)

      {:ok, plaintext} = TimeLockVault.unseal(:test_seal_until, sealed)
      assert plaintext == "secret data"
    end

    test "seals with custom resource_id" do
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      {:ok, sealed} =
        TimeLockVault.seal_until(:test_seal_until, "data", deadline, resource_id: "my-doc-123")

      {:ok, info} = TimeLockVault.inspect(:test_seal_until, sealed)
      assert info.type == :until
    end
  end

  describe "seal_after/4 and unseal/2" do
    setup %{conv_key: conv_key} do
      {:ok, _pid} =
        TimeLockVault.start_link(
          name: :test_seal_after,
          conversation_key: conv_key,
          duration: :hour
        )

      on_exit(fn ->
        catch_exit(TimeLockVault.stop(:test_seal_after))
      end)

      :ok
    end

    test "seals data for future release" do
      release_time = DateTime.add(DateTime.utc_now(), 3600, :second)

      {:ok, sealed} = TimeLockVault.seal_after(:test_seal_after, "embargoed", release_time)
      assert is_binary(sealed)

      # Should fail - not yet released
      {:error, :time_locked} = TimeLockVault.unseal(:test_seal_after, sealed)
    end

    test "unseals data after release time" do
      release_time = DateTime.add(DateTime.utc_now(), -1, :second)

      {:ok, sealed} = TimeLockVault.seal_after(:test_seal_after, "released", release_time)
      {:ok, plaintext} = TimeLockVault.unseal(:test_seal_after, sealed)

      assert plaintext == "released"
    end
  end

  describe "seal_window/5 and unseal/2" do
    setup %{conv_key: conv_key} do
      {:ok, _pid} =
        TimeLockVault.start_link(
          name: :test_seal_window,
          conversation_key: conv_key,
          duration: :hour
        )

      on_exit(fn ->
        catch_exit(TimeLockVault.stop(:test_seal_window))
      end)

      :ok
    end

    test "seals and unseals within window" do
      not_before = DateTime.add(DateTime.utc_now(), -3600, :second)
      not_after = DateTime.add(DateTime.utc_now(), 3600, :second)

      {:ok, sealed} =
        TimeLockVault.seal_window(:test_seal_window, "windowed", not_before, not_after)

      {:ok, plaintext} = TimeLockVault.unseal(:test_seal_window, sealed)
      assert plaintext == "windowed"
    end

    test "fails before window" do
      not_before = DateTime.add(DateTime.utc_now(), 3600, :second)
      not_after = DateTime.add(DateTime.utc_now(), 7200, :second)

      {:ok, sealed} =
        TimeLockVault.seal_window(:test_seal_window, "future", not_before, not_after)

      {:error, :time_locked} = TimeLockVault.unseal(:test_seal_window, sealed)
    end

    test "fails after window" do
      not_before = DateTime.add(DateTime.utc_now(), -7200, :second)
      not_after = DateTime.add(DateTime.utc_now(), -3600, :second)

      {:ok, sealed} = TimeLockVault.seal_window(:test_seal_window, "past", not_before, not_after)

      {:error, :expired} = TimeLockVault.unseal(:test_seal_window, sealed)
    end
  end

  describe "seal_for_interval/4" do
    setup %{conv_key: conv_key} do
      {:ok, _pid} =
        TimeLockVault.start_link(
          name: :test_seal_interval,
          conversation_key: conv_key,
          duration: :hour
        )

      on_exit(fn ->
        catch_exit(TimeLockVault.stop(:test_seal_interval))
      end)

      :ok
    end

    test "seals with bounded interval" do
      interval = TemporalInterval.for_duration(1, :hour)

      {:ok, sealed} =
        TimeLockVault.seal_for_interval(:test_seal_interval, "interval data", interval)

      {:ok, plaintext} = TimeLockVault.unseal(:test_seal_interval, sealed)
      assert plaintext == "interval data"
    end

    test "seals with open-ended interval" do
      interval = TemporalInterval.from_now()

      {:ok, sealed} = TimeLockVault.seal_for_interval(:test_seal_interval, "open data", interval)

      {:ok, info} = TimeLockVault.inspect(:test_seal_interval, sealed)
      assert info.type == :after
    end
  end

  describe "accessible?/2" do
    setup %{conv_key: conv_key} do
      {:ok, _pid} =
        TimeLockVault.start_link(
          name: :test_accessible,
          conversation_key: conv_key,
          duration: :hour
        )

      on_exit(fn ->
        catch_exit(TimeLockVault.stop(:test_accessible))
      end)

      :ok
    end

    test "returns true for currently accessible data" do
      not_before = DateTime.add(DateTime.utc_now(), -3600, :second)
      not_after = DateTime.add(DateTime.utc_now(), 3600, :second)

      {:ok, sealed} = TimeLockVault.seal_window(:test_accessible, "data", not_before, not_after)

      assert TimeLockVault.accessible?(:test_accessible, sealed) == true
    end

    test "returns false for time-locked data" do
      release_time = DateTime.add(DateTime.utc_now(), 3600, :second)

      {:ok, sealed} = TimeLockVault.seal_after(:test_accessible, "future", release_time)

      assert TimeLockVault.accessible?(:test_accessible, sealed) == false
    end
  end

  describe "inspect/2" do
    setup %{conv_key: conv_key} do
      {:ok, _pid} =
        TimeLockVault.start_link(
          name: :test_inspect,
          conversation_key: conv_key,
          duration: :hour
        )

      on_exit(fn ->
        catch_exit(TimeLockVault.stop(:test_inspect))
      end)

      :ok
    end

    test "returns metadata including epoch" do
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      {:ok, sealed} = TimeLockVault.seal_until(:test_inspect, "data", deadline)
      {:ok, info} = TimeLockVault.inspect(:test_inspect, sealed)

      assert is_integer(info.epoch)
      assert info.type == :until
      assert info.not_after != nil
    end
  end

  describe "key rotation integration" do
    setup %{conv_key: conv_key} do
      {:ok, _pid} =
        TimeLockVault.start_link(
          name: :test_rotation,
          conversation_key: conv_key,
          duration: :hour,
          retention_epochs: 5
        )

      on_exit(fn ->
        catch_exit(TimeLockVault.stop(:test_rotation))
      end)

      :ok
    end

    test "unseals data from current epoch" do
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      {:ok, sealed} = TimeLockVault.seal_until(:test_rotation, "current epoch", deadline)
      {:ok, plaintext} = TimeLockVault.unseal(:test_rotation, sealed)

      assert plaintext == "current epoch"
    end

    test "sealed data includes epoch number" do
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      {:ok, sealed} = TimeLockVault.seal_until(:test_rotation, "data", deadline)
      {:ok, info} = TimeLockVault.inspect(:test_rotation, sealed)

      assert info.epoch >= 0
    end
  end

  describe "error handling" do
    setup %{conv_key: conv_key} do
      {:ok, _pid} =
        TimeLockVault.start_link(
          name: :test_errors,
          conversation_key: conv_key,
          duration: :hour
        )

      on_exit(fn ->
        catch_exit(TimeLockVault.stop(:test_errors))
      end)

      :ok
    end

    test "unseal fails with invalid sealed data" do
      {:error, :invalid_sealed_data} = TimeLockVault.unseal(:test_errors, "garbage")
    end

    test "inspect fails with invalid sealed data" do
      {:error, :invalid_sealed_data} = TimeLockVault.inspect(:test_errors, "garbage")
    end
  end

  describe "multiple vaults" do
    test "vaults are isolated", %{conv_key: conv_key} do
      {:ok, root2} = KeyDerivation.generate_root_key()
      {:ok, conv_key2} = KeyDerivation.derive_conversation_key(root2, "vault2")

      {:ok, _} =
        TimeLockVault.start_link(
          name: :vault_a,
          conversation_key: conv_key
        )

      {:ok, _} =
        TimeLockVault.start_link(
          name: :vault_b,
          conversation_key: conv_key2
        )

      on_exit(fn ->
        catch_exit(TimeLockVault.stop(:vault_a))
        catch_exit(TimeLockVault.stop(:vault_b))
      end)

      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      {:ok, sealed_a} = TimeLockVault.seal_until(:vault_a, "vault A data", deadline)
      {:ok, sealed_b} = TimeLockVault.seal_until(:vault_b, "vault B data", deadline)

      # Each vault can only unseal its own data
      {:ok, "vault A data"} = TimeLockVault.unseal(:vault_a, sealed_a)
      {:ok, "vault B data"} = TimeLockVault.unseal(:vault_b, sealed_b)

      # Cross-vault unseal should fail (different keys)
      {:error, :decryption_failed} = TimeLockVault.unseal(:vault_a, sealed_b)
      {:error, :decryption_failed} = TimeLockVault.unseal(:vault_b, sealed_a)
    end
  end
end
