defmodule Tessera.Crypto.TimeLockTest do
  use ExUnit.Case, async: true

  alias Tessera.Crypto.TimeLock
  alias Tessera.Core.Rights.TemporalInterval

  # Generate a valid 32-byte key for testing
  defp generate_key, do: :crypto.strong_rand_bytes(32)

  describe "encrypt_until/3" do
    test "encrypts data successfully" do
      key = generate_key()
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      assert {:ok, ciphertext} = TimeLock.encrypt_until("secret", deadline, key)
      assert is_binary(ciphertext)
      assert byte_size(ciphertext) > byte_size("secret")
    end

    test "produces different ciphertexts for same plaintext (random nonce)" do
      key = generate_key()
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      {:ok, ct1} = TimeLock.encrypt_until("secret", deadline, key)
      {:ok, ct2} = TimeLock.encrypt_until("secret", deadline, key)

      refute ct1 == ct2
    end

    test "rejects invalid key length" do
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      assert {:error, {:invalid_key_length, 32}} =
               TimeLock.encrypt_until("secret", deadline, "short")

      assert {:error, {:invalid_key_length, 32}} =
               TimeLock.encrypt_until("secret", deadline, :crypto.strong_rand_bytes(16))
    end

    test "rejects deadline in the past" do
      key = generate_key()
      past_deadline = DateTime.add(DateTime.utc_now(), -3600, :second)

      assert {:error, :deadline_in_past} = TimeLock.encrypt_until("secret", past_deadline, key)
    end
  end

  describe "encrypt_after/3" do
    test "encrypts data successfully" do
      key = generate_key()
      release_time = DateTime.add(DateTime.utc_now(), 3600, :second)

      assert {:ok, ciphertext} = TimeLock.encrypt_after("embargoed", release_time, key)
      assert is_binary(ciphertext)
    end

    test "allows past release time (data immediately accessible)" do
      key = generate_key()
      past_time = DateTime.add(DateTime.utc_now(), -3600, :second)

      assert {:ok, _ciphertext} = TimeLock.encrypt_after("data", past_time, key)
    end
  end

  describe "encrypt_window/4" do
    test "encrypts data successfully" do
      key = generate_key()
      not_before = DateTime.utc_now()
      not_after = DateTime.add(not_before, 3600, :second)

      assert {:ok, ciphertext} = TimeLock.encrypt_window("windowed", not_before, not_after, key)
      assert is_binary(ciphertext)
    end

    test "rejects invalid window (not_before >= not_after)" do
      key = generate_key()
      now = DateTime.utc_now()

      assert {:error, :invalid_window} = TimeLock.encrypt_window("data", now, now, key)

      earlier = DateTime.add(now, -3600, :second)
      assert {:error, :invalid_window} = TimeLock.encrypt_window("data", now, earlier, key)
    end
  end

  describe "encrypt_for_interval/3" do
    test "uses after semantics for open-ended intervals" do
      key = generate_key()
      interval = TemporalInterval.from_now()

      assert {:ok, ciphertext} = TimeLock.encrypt_for_interval("data", interval, key)
      assert {:ok, %{type: :after}} = TimeLock.inspect_constraints(ciphertext)
    end

    test "uses window semantics for bounded intervals" do
      key = generate_key()
      interval = TemporalInterval.for_duration(1, :hour)

      assert {:ok, ciphertext} = TimeLock.encrypt_for_interval("data", interval, key)
      assert {:ok, %{type: :window}} = TimeLock.inspect_constraints(ciphertext)
    end
  end

  describe "decrypt/2 with encrypt_until" do
    test "decrypts before deadline" do
      key = generate_key()
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      {:ok, ciphertext} = TimeLock.encrypt_until("secret message", deadline, key)
      assert {:ok, "secret message"} = TimeLock.decrypt(ciphertext, key)
    end

    test "fails after deadline with :expired" do
      key = generate_key()

      # Use decrypt_at to simulate future time
      {:ok, ciphertext} =
        TimeLock.encrypt_until("secret", DateTime.add(DateTime.utc_now(), 10, :second), key)

      future_time = DateTime.add(DateTime.utc_now(), 20, :second)
      assert {:error, :expired} = TimeLock.decrypt_at(ciphertext, key, future_time)
    end
  end

  describe "decrypt/2 with encrypt_after" do
    test "fails before release time with :time_locked" do
      key = generate_key()
      release_time = DateTime.add(DateTime.utc_now(), 3600, :second)

      {:ok, ciphertext} = TimeLock.encrypt_after("embargoed", release_time, key)
      assert {:error, :time_locked} = TimeLock.decrypt(ciphertext, key)
    end

    test "decrypts after release time" do
      key = generate_key()
      release_time = DateTime.add(DateTime.utc_now(), -1, :second)

      {:ok, ciphertext} = TimeLock.encrypt_after("now accessible", release_time, key)
      assert {:ok, "now accessible"} = TimeLock.decrypt(ciphertext, key)
    end
  end

  describe "decrypt/2 with encrypt_window" do
    test "decrypts within window" do
      key = generate_key()
      not_before = DateTime.add(DateTime.utc_now(), -3600, :second)
      not_after = DateTime.add(DateTime.utc_now(), 3600, :second)

      {:ok, ciphertext} = TimeLock.encrypt_window("windowed data", not_before, not_after, key)
      assert {:ok, "windowed data"} = TimeLock.decrypt(ciphertext, key)
    end

    test "fails before window with :time_locked" do
      key = generate_key()
      not_before = DateTime.add(DateTime.utc_now(), 3600, :second)
      not_after = DateTime.add(DateTime.utc_now(), 7200, :second)

      {:ok, ciphertext} = TimeLock.encrypt_window("future data", not_before, not_after, key)
      assert {:error, :time_locked} = TimeLock.decrypt(ciphertext, key)
    end

    test "fails after window with :expired" do
      key = generate_key()
      not_before = DateTime.add(DateTime.utc_now(), -7200, :second)
      not_after = DateTime.add(DateTime.utc_now(), -3600, :second)

      {:ok, ciphertext} = TimeLock.encrypt_window("past data", not_before, not_after, key)
      assert {:error, :expired} = TimeLock.decrypt(ciphertext, key)
    end
  end

  describe "decrypt_at/3" do
    test "validates against provided timestamp" do
      key = generate_key()
      not_before = ~U[2024-06-01 00:00:00Z]
      not_after = ~U[2024-06-30 23:59:59Z]

      {:ok, ciphertext} = TimeLock.encrypt_window("june data", not_before, not_after, key)

      # Within window
      assert {:ok, "june data"} = TimeLock.decrypt_at(ciphertext, key, ~U[2024-06-15 12:00:00Z])

      # Before window
      assert {:error, :time_locked} =
               TimeLock.decrypt_at(ciphertext, key, ~U[2024-05-31 23:59:59Z])

      # After window
      assert {:error, :expired} = TimeLock.decrypt_at(ciphertext, key, ~U[2024-07-01 00:00:00Z])
    end
  end

  describe "decrypt/2 error cases" do
    test "fails with wrong key" do
      key1 = generate_key()
      key2 = generate_key()
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      {:ok, ciphertext} = TimeLock.encrypt_until("secret", deadline, key1)
      assert {:error, :decryption_failed} = TimeLock.decrypt(ciphertext, key2)
    end

    test "fails with invalid ciphertext" do
      key = generate_key()
      assert {:error, :invalid_ciphertext} = TimeLock.decrypt("garbage", key)
      assert {:error, :invalid_ciphertext} = TimeLock.decrypt(<<0, 1, 2, 3>>, key)
    end

    test "fails with tampered ciphertext" do
      key = generate_key()
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      {:ok, ciphertext} = TimeLock.encrypt_until("secret", deadline, key)

      # Tamper with the encrypted portion
      tampered = ciphertext <> <<0>>
      assert {:error, :decryption_failed} = TimeLock.decrypt(tampered, key)
    end
  end

  describe "inspect_constraints/1" do
    test "returns constraints for until encryption" do
      key = generate_key()
      # Use a fixed future timestamp to avoid precision issues
      deadline = ~U[2030-06-15 12:00:00Z]

      {:ok, ciphertext} = TimeLock.encrypt_until("data", deadline, key)
      {:ok, info} = TimeLock.inspect_constraints(ciphertext)

      assert info.type == :until
      assert info.not_before == nil
      assert info.not_after == deadline
      assert info.version == 1
    end

    test "returns constraints for after encryption" do
      key = generate_key()
      release_time = ~U[2024-06-01 00:00:00Z]

      {:ok, ciphertext} = TimeLock.encrypt_after("data", release_time, key)
      {:ok, info} = TimeLock.inspect_constraints(ciphertext)

      assert info.type == :after
      assert info.not_before == release_time
      assert info.not_after == nil
    end

    test "returns constraints for window encryption" do
      key = generate_key()
      not_before = ~U[2024-01-01 00:00:00Z]
      not_after = ~U[2024-03-31 23:59:59Z]

      {:ok, ciphertext} = TimeLock.encrypt_window("data", not_before, not_after, key)
      {:ok, info} = TimeLock.inspect_constraints(ciphertext)

      assert info.type == :window
      assert info.not_before == not_before
      assert info.not_after == not_after
    end

    test "returns error for invalid ciphertext" do
      assert {:error, :invalid_ciphertext} = TimeLock.inspect_constraints("garbage")
    end
  end

  describe "accessible?/1" do
    test "returns true when currently accessible" do
      key = generate_key()
      not_before = DateTime.add(DateTime.utc_now(), -3600, :second)
      not_after = DateTime.add(DateTime.utc_now(), 3600, :second)

      {:ok, ciphertext} = TimeLock.encrypt_window("data", not_before, not_after, key)
      assert TimeLock.accessible?(ciphertext) == true
    end

    test "returns false when time locked" do
      key = generate_key()
      release_time = DateTime.add(DateTime.utc_now(), 3600, :second)

      {:ok, ciphertext} = TimeLock.encrypt_after("data", release_time, key)
      assert TimeLock.accessible?(ciphertext) == false
    end

    test "returns false when expired" do
      key = generate_key()
      deadline = DateTime.add(DateTime.utc_now(), -3600, :second)
      # Need to use window to create an expired ciphertext
      not_before = DateTime.add(deadline, -7200, :second)

      {:ok, ciphertext} = TimeLock.encrypt_window("data", not_before, deadline, key)
      assert TimeLock.accessible?(ciphertext) == false
    end

    test "returns false for invalid ciphertext" do
      assert TimeLock.accessible?("garbage") == false
    end
  end

  describe "accessible_at?/2" do
    test "checks accessibility at specific time" do
      key = generate_key()
      not_before = ~U[2024-06-01 00:00:00Z]
      not_after = ~U[2024-06-30 23:59:59Z]

      {:ok, ciphertext} = TimeLock.encrypt_window("data", not_before, not_after, key)

      assert TimeLock.accessible_at?(ciphertext, ~U[2024-06-15 12:00:00Z]) == true
      assert TimeLock.accessible_at?(ciphertext, ~U[2024-05-15 12:00:00Z]) == false
      assert TimeLock.accessible_at?(ciphertext, ~U[2024-07-15 12:00:00Z]) == false
    end
  end

  describe "roundtrip encryption" do
    test "encrypts and decrypts various data sizes" do
      key = generate_key()
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      for size <- [0, 1, 16, 256, 1024, 65536] do
        data = :crypto.strong_rand_bytes(size)
        {:ok, ciphertext} = TimeLock.encrypt_until(data, deadline, key)
        {:ok, decrypted} = TimeLock.decrypt(ciphertext, key)
        assert decrypted == data, "Failed for size #{size}"
      end
    end

    test "handles unicode data" do
      key = generate_key()
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)
      unicode_data = "Hello 世界 🎉 émoji"

      {:ok, ciphertext} = TimeLock.encrypt_until(unicode_data, deadline, key)
      {:ok, decrypted} = TimeLock.decrypt(ciphertext, key)

      assert decrypted == unicode_data
    end
  end

  describe "boundary conditions" do
    test "exact deadline boundary" do
      key = generate_key()
      # Use a fixed future deadline to avoid timing precision issues
      deadline = ~U[2030-06-15 12:00:00Z]

      {:ok, ciphertext} = TimeLock.encrypt_until("data", deadline, key)

      # At exact deadline should still be accessible
      assert {:ok, "data"} = TimeLock.decrypt_at(ciphertext, key, deadline)

      # One second after should fail
      assert {:error, :expired} =
               TimeLock.decrypt_at(ciphertext, key, DateTime.add(deadline, 1, :second))
    end

    test "exact release time boundary" do
      key = generate_key()
      release_time = ~U[2024-06-15 12:00:00Z]

      {:ok, ciphertext} = TimeLock.encrypt_after("data", release_time, key)

      # At exact release time should be accessible
      assert {:ok, "data"} = TimeLock.decrypt_at(ciphertext, key, release_time)

      # One second before should fail
      assert {:error, :time_locked} =
               TimeLock.decrypt_at(ciphertext, key, DateTime.add(release_time, -1, :second))
    end
  end
end
