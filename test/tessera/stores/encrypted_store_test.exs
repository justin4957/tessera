defmodule Tessera.Stores.EncryptedStoreTest do
  use ExUnit.Case, async: true

  alias Tessera.Stores.EncryptedStore
  alias Tessera.Stores.Memory.Adapter, as: MemoryStore
  alias Tessera.Crypto.TimeLockVault
  alias Tessera.Crypto.KeyDerivation
  alias Tessera.Core.Rights.TemporalInterval

  # Use unique names per test for isolation
  setup do
    suffix = :erlang.unique_integer([:positive])

    # Generate keys
    {:ok, root_key} = KeyDerivation.generate_root_key()
    {:ok, conv_key} = KeyDerivation.derive_conversation_key(root_key, "test_#{suffix}")

    # Start vault
    vault_name = :"vault_#{suffix}"

    {:ok, vault_pid} =
      TimeLockVault.start_link(
        name: vault_name,
        conversation_key: conv_key,
        duration: :hour
      )

    # Start memory store
    store_name = :"store_#{suffix}"
    table_name = :"table_#{suffix}"

    {:ok, store_pid} =
      MemoryStore.start_link(
        name: store_name,
        table_name: table_name
      )

    # Start encrypted store
    encrypted_store_name = :"encrypted_store_#{suffix}"

    {:ok, encrypted_store_pid} =
      EncryptedStore.start_link(
        name: encrypted_store_name,
        vault: vault_name,
        store: store_name
      )

    on_exit(fn ->
      if Process.alive?(encrypted_store_pid), do: GenServer.stop(encrypted_store_pid)
      if Process.alive?(store_pid), do: GenServer.stop(store_pid)
      if Process.alive?(vault_pid), do: GenServer.stop(vault_pid)
    end)

    {:ok, server: encrypted_store_name, vault: vault_name, store: store_name, conv_key: conv_key}
  end

  # ============================================================================
  # Basic Encrypted Storage Tests
  # ============================================================================

  describe "put_encrypted/4 with :until" do
    test "stores encrypted data with deadline", %{server: server} do
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      result =
        EncryptedStore.put_encrypted(
          server,
          "resource/1",
          "secret data",
          until: deadline
        )

      assert result == :ok
    end

    test "stored data is actually encrypted", %{server: server, store: store} do
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      :ok =
        EncryptedStore.put_encrypted(
          server,
          "resource/1",
          "secret data",
          until: deadline
        )

      # Get raw data from underlying store
      {:ok, raw_data, metadata} = MemoryStore.get("resource/1", store)

      # Data should be encrypted (binary, not plaintext)
      assert is_binary(raw_data)
      refute raw_data == "secret data"
      assert metadata.encrypted == true
      assert metadata.encryption_mode == :until
    end
  end

  describe "put_encrypted/4 with :after" do
    test "stores data accessible after release time", %{server: server} do
      # Data accessible after 1 second from now
      release_time = DateTime.add(DateTime.utc_now(), 1, :second)

      :ok =
        EncryptedStore.put_encrypted(
          server,
          "resource/1",
          "embargoed data",
          after: release_time
        )

      # Should not be accessible yet
      assert {:error, :time_locked} = EncryptedStore.get_decrypted(server, "resource/1")

      # Wait for release
      Process.sleep(1100)

      # Now should be accessible
      {:ok, data, _meta} = EncryptedStore.get_decrypted(server, "resource/1")
      assert data == "embargoed data"
    end
  end

  describe "put_encrypted/4 with :window" do
    test "stores data accessible within time window", %{server: server} do
      now = DateTime.utc_now()
      not_before = DateTime.add(now, -3600, :second)
      not_after = DateTime.add(now, 3600, :second)

      :ok =
        EncryptedStore.put_encrypted(
          server,
          "resource/1",
          "windowed data",
          window: {not_before, not_after}
        )

      {:ok, data, metadata} = EncryptedStore.get_decrypted(server, "resource/1")
      assert data == "windowed data"
      assert metadata.encryption_mode == :window
    end
  end

  describe "put_encrypted/4 with :interval" do
    test "stores data accessible during interval", %{server: server} do
      interval = TemporalInterval.for_duration(1, :hour)

      :ok =
        EncryptedStore.put_encrypted(
          server,
          "resource/1",
          "interval data",
          interval: interval
        )

      {:ok, data, metadata} = EncryptedStore.get_decrypted(server, "resource/1")
      assert data == "interval data"
      assert metadata.encryption_mode == :interval
    end
  end

  # ============================================================================
  # Decryption Tests
  # ============================================================================

  describe "get_decrypted/2" do
    test "decrypts accessible data", %{server: server} do
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      :ok =
        EncryptedStore.put_encrypted(
          server,
          "resource/1",
          "secret data",
          until: deadline
        )

      {:ok, data, metadata} = EncryptedStore.get_decrypted(server, "resource/1")

      assert data == "secret data"
      assert metadata.encrypted == true
      assert metadata.encryption_mode == :until
      assert metadata.encrypted_at != nil
    end

    test "returns not_found for missing resource", %{server: server} do
      assert {:error, :not_found} = EncryptedStore.get_decrypted(server, "nonexistent")
    end

    test "returns error for unencrypted data", %{server: server} do
      :ok = EncryptedStore.put(server, "resource/1", "plain data", %{})

      assert {:error, :not_encrypted} = EncryptedStore.get_decrypted(server, "resource/1")
    end

    test "returns time_locked for data before access window", %{server: server} do
      # Data accessible 1 hour from now
      release_time = DateTime.add(DateTime.utc_now(), 3600, :second)

      :ok =
        EncryptedStore.put_encrypted(
          server,
          "resource/1",
          "future data",
          after: release_time
        )

      assert {:error, :time_locked} = EncryptedStore.get_decrypted(server, "resource/1")
    end

    test "returns expired for data past access window", %{server: server} do
      # Data was accessible until 1 second ago
      deadline = DateTime.add(DateTime.utc_now(), -1, :second)

      :ok =
        EncryptedStore.put_encrypted(
          server,
          "resource/1",
          "expired data",
          until: deadline
        )

      assert {:error, :expired} = EncryptedStore.get_decrypted(server, "resource/1")
    end
  end

  # ============================================================================
  # Transparent get/put Tests
  # ============================================================================

  describe "get/2 (transparent)" do
    test "decrypts encrypted data automatically", %{server: server} do
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      :ok =
        EncryptedStore.put_encrypted(
          server,
          "resource/1",
          "secret data",
          until: deadline
        )

      {:ok, data, _metadata} = EncryptedStore.get(server, "resource/1")
      assert data == "secret data"
    end

    test "returns unencrypted data directly", %{server: server} do
      :ok = EncryptedStore.put(server, "resource/1", "plain data", %{custom: "meta"})

      {:ok, data, metadata} = EncryptedStore.get(server, "resource/1")
      assert data == "plain data"
      assert metadata.custom == "meta"
      assert metadata.encrypted == false
    end
  end

  describe "put/4 (unencrypted)" do
    test "stores data without encryption", %{server: server, store: store} do
      :ok = EncryptedStore.put(server, "resource/1", "plain data", %{custom: "value"})

      # Raw data should be plaintext
      {:ok, raw_data, metadata} = MemoryStore.get("resource/1", store)
      assert raw_data == "plain data"
      assert metadata.encrypted == false
      assert metadata.custom == "value"
    end
  end

  # ============================================================================
  # CRUD Operations Tests
  # ============================================================================

  describe "delete/2" do
    test "deletes encrypted data", %{server: server} do
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      :ok =
        EncryptedStore.put_encrypted(
          server,
          "resource/1",
          "secret",
          until: deadline
        )

      assert :ok = EncryptedStore.delete(server, "resource/1")
      assert {:error, :not_found} = EncryptedStore.get(server, "resource/1")
    end

    test "returns not_found for missing resource", %{server: server} do
      assert {:error, :not_found} = EncryptedStore.delete(server, "nonexistent")
    end
  end

  describe "list/2" do
    test "lists all resources", %{server: server} do
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      :ok = EncryptedStore.put_encrypted(server, "resource/1", "data1", until: deadline)
      :ok = EncryptedStore.put_encrypted(server, "resource/2", "data2", until: deadline)
      :ok = EncryptedStore.put(server, "other/1", "data3", %{})

      {:ok, resources} = EncryptedStore.list(server, nil)
      assert length(resources) == 3
      assert "resource/1" in resources
      assert "resource/2" in resources
      assert "other/1" in resources
    end

    test "lists resources with prefix filter", %{server: server} do
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      :ok = EncryptedStore.put_encrypted(server, "resource/1", "data1", until: deadline)
      :ok = EncryptedStore.put_encrypted(server, "resource/2", "data2", until: deadline)
      :ok = EncryptedStore.put(server, "other/1", "data3", %{})

      {:ok, resources} = EncryptedStore.list(server, "resource/")
      assert length(resources) == 2
      assert "resource/1" in resources
      assert "resource/2" in resources
    end
  end

  describe "exists?/2" do
    test "returns true for existing resource", %{server: server} do
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)
      :ok = EncryptedStore.put_encrypted(server, "resource/1", "data", until: deadline)

      assert EncryptedStore.exists?(server, "resource/1") == true
    end

    test "returns false for missing resource", %{server: server} do
      assert EncryptedStore.exists?(server, "nonexistent") == false
    end
  end

  # ============================================================================
  # Accessibility Tests
  # ============================================================================

  describe "accessible?/2" do
    test "returns true for accessible encrypted data", %{server: server} do
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)
      :ok = EncryptedStore.put_encrypted(server, "resource/1", "data", until: deadline)

      assert EncryptedStore.accessible?(server, "resource/1") == true
    end

    test "returns false for time-locked data", %{server: server} do
      release_time = DateTime.add(DateTime.utc_now(), 3600, :second)
      :ok = EncryptedStore.put_encrypted(server, "resource/1", "data", after: release_time)

      assert EncryptedStore.accessible?(server, "resource/1") == false
    end

    test "returns false for expired data", %{server: server} do
      deadline = DateTime.add(DateTime.utc_now(), -1, :second)
      :ok = EncryptedStore.put_encrypted(server, "resource/1", "data", until: deadline)

      assert EncryptedStore.accessible?(server, "resource/1") == false
    end

    test "returns true for unencrypted data", %{server: server} do
      :ok = EncryptedStore.put(server, "resource/1", "plain", %{})

      assert EncryptedStore.accessible?(server, "resource/1") == true
    end

    test "returns false for missing resource", %{server: server} do
      assert EncryptedStore.accessible?(server, "nonexistent") == false
    end
  end

  # ============================================================================
  # Metadata Inspection Tests
  # ============================================================================

  describe "inspect_encryption/2" do
    test "returns encryption metadata for encrypted data", %{server: server} do
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      :ok =
        EncryptedStore.put_encrypted(
          server,
          "resource/1",
          "data",
          until: deadline,
          metadata: %{custom: "value"}
        )

      {:ok, info} = EncryptedStore.inspect_encryption(server, "resource/1")

      assert info.encrypted == true
      assert info.encryption_mode == :until
      assert info.custom == "value"
      assert info.vault_info != nil
      assert info.vault_info.epoch != nil
    end

    test "returns not_found for missing resource", %{server: server} do
      assert {:error, :not_found} = EncryptedStore.inspect_encryption(server, "nonexistent")
    end

    test "returns metadata for unencrypted data", %{server: server} do
      :ok = EncryptedStore.put(server, "resource/1", "plain", %{custom: "value"})

      {:ok, info} = EncryptedStore.inspect_encryption(server, "resource/1")

      assert info.encrypted == false
      assert info.custom == "value"
    end
  end

  # ============================================================================
  # Info Tests
  # ============================================================================

  describe "info/1" do
    test "returns store information", %{server: server, vault: vault, store: store} do
      info = EncryptedStore.info(server)

      assert info.type == :encrypted_store
      assert info.vault == vault
      assert info.store == store
      assert :encrypted_storage in info.capabilities
      assert :time_constraints in info.capabilities
      assert info.store_info != nil
    end
  end

  # ============================================================================
  # Error Handling Tests
  # ============================================================================

  describe "error handling" do
    test "returns error for missing encryption constraints", %{server: server} do
      result = EncryptedStore.put_encrypted(server, "resource/1", "data", [])

      assert {:error, :missing_encryption_constraints} = result
    end

    test "returns error for invalid window format", %{server: server} do
      result = EncryptedStore.put_encrypted(server, "resource/1", "data", window: "invalid")

      assert {:error, :invalid_window} = result
    end
  end

  # ============================================================================
  # Custom Metadata Tests
  # ============================================================================

  describe "custom metadata" do
    test "preserves custom metadata with encryption", %{server: server} do
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      :ok =
        EncryptedStore.put_encrypted(
          server,
          "resource/1",
          "data",
          until: deadline,
          metadata: %{
            content_type: "application/json",
            author: "alice",
            tags: ["important", "confidential"]
          }
        )

      {:ok, _data, metadata} = EncryptedStore.get_decrypted(server, "resource/1")

      assert metadata.content_type == "application/json"
      assert metadata.author == "alice"
      assert metadata.tags == ["important", "confidential"]
      assert metadata.encrypted == true
    end
  end

  # ============================================================================
  # Binary Data Tests
  # ============================================================================

  describe "binary data handling" do
    test "handles arbitrary binary data", %{server: server} do
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)
      binary_data = :crypto.strong_rand_bytes(1024)

      :ok =
        EncryptedStore.put_encrypted(
          server,
          "resource/1",
          binary_data,
          until: deadline
        )

      {:ok, decrypted, _meta} = EncryptedStore.get_decrypted(server, "resource/1")
      assert decrypted == binary_data
    end

    test "handles empty binary", %{server: server} do
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      :ok =
        EncryptedStore.put_encrypted(
          server,
          "resource/1",
          "",
          until: deadline
        )

      {:ok, decrypted, _meta} = EncryptedStore.get_decrypted(server, "resource/1")
      assert decrypted == ""
    end
  end

  # ============================================================================
  # Integration Tests
  # ============================================================================

  describe "full workflow" do
    test "stores, queries, and retrieves encrypted data", %{server: server} do
      deadline = DateTime.add(DateTime.utc_now(), 3600, :second)

      # Store multiple encrypted resources
      for i <- 1..5 do
        :ok =
          EncryptedStore.put_encrypted(
            server,
            "docs/#{i}",
            "document #{i}",
            until: deadline,
            metadata: %{index: i}
          )
      end

      # List all docs
      {:ok, resources} = EncryptedStore.list(server, "docs/")
      assert length(resources) == 5

      # Check accessibility
      for i <- 1..5 do
        assert EncryptedStore.accessible?(server, "docs/#{i}")
      end

      # Retrieve and verify
      for i <- 1..5 do
        {:ok, data, meta} = EncryptedStore.get_decrypted(server, "docs/#{i}")
        assert data == "document #{i}"
        assert meta.index == i
      end

      # Delete one
      :ok = EncryptedStore.delete(server, "docs/3")
      {:ok, remaining} = EncryptedStore.list(server, "docs/")
      assert length(remaining) == 4
      refute "docs/3" in remaining
    end
  end
end
