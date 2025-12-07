defmodule Tessera.AttestationTest do
  use ExUnit.Case, async: true

  alias Tessera.Attestation
  alias Tessera.Attestation.{Event, Batch}
  alias Tessera.Attestation.Adapters.Memory

  describe "generate_id/0" do
    test "generates unique IDs" do
      ids = for _ <- 1..100, do: Attestation.generate_id()
      assert length(Enum.uniq(ids)) == 100
    end

    test "generates 32-character hex strings" do
      id = Attestation.generate_id()
      assert String.length(id) == 32
      assert String.match?(id, ~r/^[0-9a-f]+$/)
    end
  end

  describe "hash_event/2" do
    test "produces consistent hashes for same input" do
      event_data = %{pod_id: "pod_123", creator: "user_1"}

      hash1 = Attestation.hash_event(:pod_creation, event_data)
      hash2 = Attestation.hash_event(:pod_creation, event_data)

      assert hash1 == hash2
    end

    test "produces different hashes for different event types" do
      event_data = %{id: "test"}

      hash1 = Attestation.hash_event(:pod_creation, event_data)
      hash2 = Attestation.hash_event(:grant_issuance, event_data)

      assert hash1 != hash2
    end

    test "produces different hashes for different data" do
      hash1 = Attestation.hash_event(:pod_creation, %{pod_id: "pod_1"})
      hash2 = Attestation.hash_event(:pod_creation, %{pod_id: "pod_2"})

      assert hash1 != hash2
    end

    test "produces 32-byte SHA-256 hashes" do
      hash = Attestation.hash_event(:pod_creation, %{test: true})
      assert byte_size(hash) == 32
    end
  end

  describe "valid_event_type?/1" do
    test "returns true for valid event types" do
      valid_types = [
        :pod_creation,
        :grant_issuance,
        :grant_revocation,
        :consensus_outcome,
        :key_rotation,
        :epoch_boundary
      ]

      for type <- valid_types do
        assert Attestation.valid_event_type?(type), "Expected #{type} to be valid"
      end
    end

    test "returns false for invalid event types" do
      assert not Attestation.valid_event_type?(:invalid_type)
      assert not Attestation.valid_event_type?(:random)
      assert not Attestation.valid_event_type?("pod_creation")
    end
  end
end

defmodule Tessera.Attestation.EventTest do
  use ExUnit.Case, async: true

  alias Tessera.Attestation.Event

  describe "new/2" do
    test "creates an event with valid type" do
      {:ok, event} = Event.new(:pod_creation, %{pod_id: "test"})

      assert event.type == :pod_creation
      assert event.data == %{pod_id: "test"}
      assert is_binary(event.id)
      assert byte_size(event.hash) == 32
      assert %DateTime{} = event.created_at
    end

    test "returns error for invalid event type" do
      assert {:error, :invalid_event_type} = Event.new(:invalid, %{})
    end
  end

  describe "pod_creation/3" do
    test "creates a pod creation event" do
      {:ok, event} = Event.pod_creation("pod_123", "user_1", metadata: %{name: "Test Pod"})

      assert event.type == :pod_creation
      assert event.data.pod_id == "pod_123"
      assert event.data.creator_id == "user_1"
      assert event.data.metadata == %{name: "Test Pod"}
      assert %DateTime{} = event.data.timestamp
    end
  end

  describe "grant_issuance/4" do
    test "creates a grant issuance event" do
      {:ok, event} =
        Event.grant_issuance("grant_1", "grantor", "grantee",
          resource_id: "resource_1",
          permissions: [:read, :write]
        )

      assert event.type == :grant_issuance
      assert event.data.grant_id == "grant_1"
      assert event.data.grantor_id == "grantor"
      assert event.data.grantee_id == "grantee"
      assert event.data.resource_id == "resource_1"
      assert event.data.permissions == [:read, :write]
    end
  end

  describe "grant_revocation/3" do
    test "creates a grant revocation event" do
      {:ok, event} = Event.grant_revocation("grant_1", "revoker", reason: "expired")

      assert event.type == :grant_revocation
      assert event.data.grant_id == "grant_1"
      assert event.data.revoker_id == "revoker"
      assert event.data.reason == "expired"
    end
  end

  describe "consensus_outcome/3" do
    test "creates a consensus outcome event" do
      outcome = %{decision: :approved, votes: 5}

      {:ok, event} =
        Event.consensus_outcome("pod_1", outcome,
          participants: ["user_1", "user_2"],
          round: 3
        )

      assert event.type == :consensus_outcome
      assert event.data.pod_id == "pod_1"
      assert event.data.outcome == outcome
      assert event.data.participants == ["user_1", "user_2"]
      assert event.data.round == 3
    end
  end

  describe "key_rotation/3" do
    test "creates a key rotation event" do
      {:ok, event} =
        Event.key_rotation("pod_1", 5, key_commitment: "abc123")

      assert event.type == :key_rotation
      assert event.data.pod_id == "pod_1"
      assert event.data.epoch_number == 5
      assert event.data.previous_epoch == 4
      assert event.data.key_commitment == "abc123"
    end
  end

  describe "epoch_boundary/3" do
    test "creates an epoch boundary event" do
      boundary_time = DateTime.utc_now()

      {:ok, event} =
        Event.epoch_boundary(10, boundary_time,
          previous_epoch_hash: "hash123",
          pod_count: 42
        )

      assert event.type == :epoch_boundary
      assert event.data.epoch_number == 10
      assert event.data.boundary_time == boundary_time
      assert event.data.previous_epoch_hash == "hash123"
      assert event.data.pod_count == 42
    end
  end

  describe "serialization" do
    test "serializes and deserializes an event" do
      {:ok, original} = Event.pod_creation("pod_1", "user_1")
      {:ok, serialized} = Event.serialize(original)

      assert is_binary(serialized)

      {:ok, deserialized} = Event.deserialize(serialized)

      assert deserialized.id == original.id
      assert deserialized.type == original.type
      assert deserialized.data.pod_id == original.data.pod_id
      assert deserialized.hash == original.hash
    end
  end
end

defmodule Tessera.Attestation.BatchTest do
  use ExUnit.Case, async: true

  alias Tessera.Attestation.{Event, Batch}

  setup do
    events =
      for i <- 1..5 do
        {:ok, event} = Event.pod_creation("pod_#{i}", "user_#{i}")
        event
      end

    {:ok, events: events}
  end

  describe "new/2" do
    test "creates a batch from events", %{events: events} do
      {:ok, batch} = Batch.new(events)

      assert length(batch.events) == 5
      assert byte_size(batch.merkle_root) == 32
      assert is_list(batch.merkle_tree)
      assert batch.status == :pending
    end

    test "returns error for empty batch" do
      assert {:error, :empty_batch} = Batch.new([])
    end

    test "returns error for batch exceeding max size" do
      events =
        for i <- 1..150,
            do: %Event{
              id: "e_#{i}",
              type: :pod_creation,
              data: %{},
              hash: :crypto.hash(:sha256, "#{i}"),
              created_at: DateTime.utc_now()
            }

      assert {:error, {:batch_too_large, 100}} = Batch.new(events)
    end

    test "respects custom max size" do
      events =
        for i <- 1..10,
            do: %Event{
              id: "e_#{i}",
              type: :pod_creation,
              data: %{},
              hash: :crypto.hash(:sha256, "#{i}"),
              created_at: DateTime.utc_now()
            }

      assert {:error, {:batch_too_large, 5}} = Batch.new(events, max_size: 5)
    end
  end

  describe "get_proof/2" do
    test "returns proof for existing event", %{events: events} do
      {:ok, batch} = Batch.new(events)
      event = Enum.at(events, 2)

      {:ok, proof} = Batch.get_proof(batch, event.id)

      assert is_list(proof)
      assert length(proof) > 0
    end

    test "returns error for non-existent event", %{events: events} do
      {:ok, batch} = Batch.new(events)

      assert {:error, :event_not_found} = Batch.get_proof(batch, "nonexistent")
    end
  end

  describe "verify_inclusion/3" do
    test "verifies valid inclusion proof", %{events: events} do
      {:ok, batch} = Batch.new(events)
      event = Enum.at(events, 2)

      {:ok, proof} = Batch.get_proof(batch, event.id)

      assert :ok = Batch.verify_inclusion(batch.merkle_root, event.hash, proof)
    end

    test "rejects invalid proof", %{events: events} do
      {:ok, batch} = Batch.new(events)
      event = Enum.at(events, 0)

      # Tampered proof
      fake_proof = [{:crypto.strong_rand_bytes(32), 0}]

      assert {:error, :invalid_proof} =
               Batch.verify_inclusion(batch.merkle_root, event.hash, fake_proof)
    end

    test "rejects wrong event hash", %{events: events} do
      {:ok, batch} = Batch.new(events)
      event = Enum.at(events, 0)

      {:ok, proof} = Batch.get_proof(batch, event.id)

      wrong_hash = :crypto.strong_rand_bytes(32)

      assert {:error, :invalid_proof} =
               Batch.verify_inclusion(batch.merkle_root, wrong_hash, proof)
    end
  end

  describe "confirm/4" do
    test "updates batch with confirmation details", %{events: events} do
      {:ok, batch} = Batch.new(events)

      confirmed = Batch.confirm(batch, "0xabc123", 12345, :ethereum)

      assert confirmed.tx_hash == "0xabc123"
      assert confirmed.block_number == 12345
      assert confirmed.chain == :ethereum
      assert confirmed.status == :confirmed
    end
  end

  describe "size/1 and event_ids/1" do
    test "returns correct size and IDs", %{events: events} do
      {:ok, batch} = Batch.new(events)

      assert Batch.size(batch) == 5
      assert length(Batch.event_ids(batch)) == 5

      event_ids = Batch.event_ids(batch)
      assert Enum.all?(events, fn e -> e.id in event_ids end)
    end
  end

  describe "merkle tree properties" do
    test "different events produce different roots" do
      {:ok, e1} = Event.pod_creation("pod_1", "user_1")
      {:ok, e2} = Event.pod_creation("pod_2", "user_2")

      {:ok, batch1} = Batch.new([e1])
      {:ok, batch2} = Batch.new([e2])

      assert batch1.merkle_root != batch2.merkle_root
    end

    test "same events in same order produce same root" do
      events =
        for i <- 1..3 do
          # Use deterministic data to ensure same hashes
          %Event{
            id: "fixed_#{i}",
            type: :pod_creation,
            data: %{pod_id: "pod_#{i}"},
            hash: :crypto.hash(:sha256, "deterministic_#{i}"),
            created_at: ~U[2024-01-01 00:00:00Z]
          }
        end

      {:ok, batch1} = Batch.new(events)
      {:ok, batch2} = Batch.new(events)

      assert batch1.merkle_root == batch2.merkle_root
    end

    test "handles single event batch" do
      {:ok, event} = Event.pod_creation("pod_1", "user_1")
      {:ok, batch} = Batch.new([event])

      assert Batch.size(batch) == 1
      assert byte_size(batch.merkle_root) == 32

      {:ok, proof} = Batch.get_proof(batch, event.id)
      assert :ok = Batch.verify_inclusion(batch.merkle_root, event.hash, proof)
    end

    test "handles odd number of events" do
      events =
        for i <- 1..7 do
          {:ok, e} = Event.pod_creation("pod_#{i}", "user_#{i}")
          e
        end

      {:ok, batch} = Batch.new(events)

      # Verify all events can be proven
      for event <- events do
        {:ok, proof} = Batch.get_proof(batch, event.id)
        assert :ok = Batch.verify_inclusion(batch.merkle_root, event.hash, proof)
      end
    end
  end
end

defmodule Tessera.Attestation.Adapters.MemoryTest do
  use ExUnit.Case

  alias Tessera.Attestation.Adapters.Memory
  alias Tessera.Attestation.Batch

  setup do
    start_supervised!(Memory)
    Memory.clear()
    :ok
  end

  describe "attest/3" do
    test "creates a single attestation" do
      {:ok, attestation} = Memory.attest(:pod_creation, %{pod_id: "pod_123"})

      assert is_binary(attestation.id)
      assert attestation.event_type == :pod_creation
      assert attestation.chain == :memory
      assert attestation.status == :confirmed
      assert String.starts_with?(attestation.tx_hash, "0x")
    end

    test "creates attestations with unique IDs" do
      {:ok, a1} = Memory.attest(:pod_creation, %{pod_id: "pod_1"})
      {:ok, a2} = Memory.attest(:pod_creation, %{pod_id: "pod_2"})

      assert a1.id != a2.id
      assert a1.tx_hash != a2.tx_hash
    end
  end

  describe "verify/1" do
    test "verifies existing attestation" do
      {:ok, attestation} = Memory.attest(:pod_creation, %{pod_id: "pod_123"})
      {:ok, verification} = Memory.verify(attestation.id)

      assert verification.valid == true
      assert verification.tx_hash == attestation.tx_hash
      assert verification.block_number == attestation.block_number
      assert verification.confirmations >= 0
    end

    test "returns error for non-existent attestation" do
      assert {:error, :not_found} = Memory.verify("nonexistent")
    end
  end

  describe "batch_attest/2" do
    test "creates a batch attestation" do
      events = [
        {:pod_creation, %{pod_id: "pod_1"}},
        {:pod_creation, %{pod_id: "pod_2"}},
        {:grant_issuance, %{grant_id: "grant_1", grantor_id: "u1", grantee_id: "u2"}}
      ]

      {:ok, batch} = Memory.batch_attest(events)

      assert is_binary(batch.id)
      assert batch.event_count == 3
      assert byte_size(batch.merkle_root) == 32
      assert batch.chain == :memory
      assert batch.status == :confirmed
    end

    test "individual events can be verified" do
      events = [
        {:pod_creation, %{pod_id: "pod_1"}},
        {:pod_creation, %{pod_id: "pod_2"}}
      ]

      {:ok, batch} = Memory.batch_attest(events)

      # Verify each event exists
      for event_id <- batch.event_ids do
        {:ok, verification} = Memory.verify(event_id)
        assert verification.valid == true
      end
    end
  end

  describe "verify_batch_inclusion/3" do
    test "verifies event is in batch" do
      events = [
        {:pod_creation, %{pod_id: "pod_1"}},
        {:pod_creation, %{pod_id: "pod_2"}}
      ]

      {:ok, batch_record} = Memory.batch_attest(events)

      # Get proof for first event
      batch = batch_record.batch
      event_id = Enum.at(batch.events, 0).id
      {:ok, proof} = Batch.get_proof(batch, event_id)

      {:ok, verification} = Memory.verify_batch_inclusion(batch.id, event_id, proof)

      assert verification.valid == true
    end

    test "rejects invalid proof" do
      events = [
        {:pod_creation, %{pod_id: "pod_1"}},
        {:pod_creation, %{pod_id: "pod_2"}}
      ]

      {:ok, batch_record} = Memory.batch_attest(events)

      batch = batch_record.batch
      event_id = Enum.at(batch.events, 0).id
      fake_proof = [{:crypto.strong_rand_bytes(32), 0}]

      assert {:error, :invalid_proof} =
               Memory.verify_batch_inclusion(batch.id, event_id, fake_proof)
    end
  end

  describe "info/0" do
    test "returns adapter information" do
      info = Memory.info()

      assert info.chain == :memory
      assert info.network == "local"
      assert info.connected == true
      assert info.contract_address == nil
    end
  end

  describe "configuration" do
    test "simulates delays" do
      Memory.configure(simulated_delay_ms: 50)

      start_time = System.monotonic_time(:millisecond)
      {:ok, _} = Memory.attest(:pod_creation, %{pod_id: "test"})
      elapsed = System.monotonic_time(:millisecond) - start_time

      assert elapsed >= 50

      # Reset
      Memory.configure(simulated_delay_ms: 0)
    end

    test "simulates failures" do
      Memory.configure(failure_rate: 1.0)

      assert {:error, :simulated_failure} = Memory.attest(:pod_creation, %{pod_id: "test"})

      # Reset
      Memory.configure(failure_rate: 0.0)
    end
  end

  describe "clear/0 and all/0" do
    test "clears all attestations" do
      {:ok, _} = Memory.attest(:pod_creation, %{pod_id: "pod_1"})
      {:ok, _} = Memory.attest(:pod_creation, %{pod_id: "pod_2"})

      assert length(Memory.all()) == 2

      Memory.clear()

      assert Memory.all() == []
    end
  end
end
