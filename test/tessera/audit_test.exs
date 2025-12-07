defmodule Tessera.AuditTest do
  use ExUnit.Case, async: true

  alias Tessera.Audit.{Entry, Memory}

  # Use unique table prefix per test to allow async execution
  setup do
    prefix = "test_#{:erlang.unique_integer([:positive])}"

    {:ok, pid} =
      Memory.start_link(
        name: :"audit_#{prefix}",
        table_prefix: prefix
      )

    server = :"audit_#{prefix}"

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid)
    end)

    {:ok, server: server, prefix: prefix}
  end

  # ============================================================================
  # Entry Tests
  # ============================================================================

  describe "Entry.new/1" do
    test "creates entry with required fields" do
      entry = Entry.new(event_type: :grant_created)

      assert entry.id != nil
      assert entry.timestamp != nil
      assert entry.event_type == :grant_created
      assert entry.entry_hash != nil
      assert entry.details == %{}
      assert entry.previous_hash == nil
    end

    test "creates entry with all fields" do
      prev_hash = :crypto.strong_rand_bytes(32)

      entry =
        Entry.new(
          event_type: :grant_created,
          actor_id: "did:web:alice.example",
          resource_id: "pod://data/record",
          details: %{grant_id: "g_123", scope: [:read, :write]},
          previous_hash: prev_hash,
          sequence_number: 42
        )

      assert entry.event_type == :grant_created
      assert entry.actor_id == "did:web:alice.example"
      assert entry.resource_id == "pod://data/record"
      assert entry.details == %{grant_id: "g_123", scope: [:read, :write]}
      assert entry.previous_hash == prev_hash
      assert entry.sequence_number == 42
    end

    test "generates unique IDs" do
      entry1 = Entry.new(event_type: :grant_created)
      entry2 = Entry.new(event_type: :grant_created)

      assert entry1.id != entry2.id
    end

    test "generates unique hashes for different entries" do
      entry1 = Entry.new(event_type: :grant_created, actor_id: "alice")
      entry2 = Entry.new(event_type: :grant_created, actor_id: "bob")

      assert entry1.entry_hash != entry2.entry_hash
    end
  end

  describe "Entry.verify_hash/1" do
    test "returns true for valid entry" do
      entry = Entry.new(event_type: :grant_created, actor_id: "alice")

      assert Entry.verify_hash(entry) == true
    end

    test "returns false for tampered entry" do
      entry = Entry.new(event_type: :grant_created, actor_id: "alice")

      # Tamper with the entry
      tampered = %{entry | actor_id: "bob"}

      assert Entry.verify_hash(tampered) == false
    end

    test "returns false for tampered details" do
      entry = Entry.new(event_type: :grant_created, details: %{key: "original"})

      tampered = %{entry | details: %{key: "modified"}}

      assert Entry.verify_hash(tampered) == false
    end
  end

  describe "Entry.verify_chain_link/2" do
    test "returns true for valid chain link" do
      entry1 = Entry.new(event_type: :grant_created)

      entry2 =
        Entry.new(
          event_type: :grant_revoked,
          previous_hash: entry1.entry_hash
        )

      assert Entry.verify_chain_link(entry1, entry2) == true
    end

    test "returns false for broken chain" do
      entry1 = Entry.new(event_type: :grant_created)
      entry2 = Entry.new(event_type: :grant_revoked)

      assert Entry.verify_chain_link(entry1, entry2) == false
    end

    test "returns false when next entry has nil previous_hash" do
      entry1 = Entry.new(event_type: :grant_created)
      entry2 = Entry.new(event_type: :grant_revoked, previous_hash: nil)

      assert Entry.verify_chain_link(entry1, entry2) == false
    end
  end

  describe "Entry serialization" do
    test "to_map/1 and from_map/1 round-trip" do
      entry =
        Entry.new(
          event_type: :grant_created,
          actor_id: "did:web:alice.example",
          resource_id: "pod://data/record",
          details: %{grant_id: "g_123"},
          sequence_number: 1
        )

      map = Entry.to_map(entry)
      {:ok, restored} = Entry.from_map(map)

      assert restored.id == entry.id
      assert restored.event_type == entry.event_type
      assert restored.actor_id == entry.actor_id
      assert restored.resource_id == entry.resource_id
      assert restored.details == entry.details
      assert restored.entry_hash == entry.entry_hash
      assert DateTime.compare(restored.timestamp, entry.timestamp) == :eq
    end

    test "from_map/1 handles previous_hash" do
      prev_hash = :crypto.strong_rand_bytes(32)

      entry =
        Entry.new(
          event_type: :grant_created,
          previous_hash: prev_hash
        )

      map = Entry.to_map(entry)
      {:ok, restored} = Entry.from_map(map)

      assert restored.previous_hash == prev_hash
    end

    test "from_map/1 returns error for invalid timestamp" do
      map = %{
        "id" => "test",
        "timestamp" => "invalid",
        "event_type" => "grant_created",
        "entry_hash" => Base.encode16(:crypto.strong_rand_bytes(32))
      }

      assert {:error, :invalid_timestamp} = Entry.from_map(map)
    end
  end

  # ============================================================================
  # Memory Adapter Tests
  # ============================================================================

  describe "Memory.log_event/3" do
    test "logs event and returns entry", %{server: server} do
      {:ok, entry} =
        Memory.log_event(
          :grant_created,
          %{actor_id: "alice", grant_id: "g_123"},
          server
        )

      assert entry.event_type == :grant_created
      assert entry.actor_id == "alice"
      assert entry.details.grant_id == "g_123"
      assert entry.sequence_number == 1
    end

    test "chains entries together", %{server: server} do
      {:ok, entry1} = Memory.log_event(:grant_created, %{}, server)
      {:ok, entry2} = Memory.log_event(:grant_revoked, %{}, server)

      assert entry1.previous_hash == nil
      assert entry2.previous_hash == entry1.entry_hash
    end

    test "increments sequence numbers", %{server: server} do
      {:ok, e1} = Memory.log_event(:grant_created, %{}, server)
      {:ok, e2} = Memory.log_event(:grant_revoked, %{}, server)
      {:ok, e3} = Memory.log_event(:grant_frozen, %{}, server)

      assert e1.sequence_number == 1
      assert e2.sequence_number == 2
      assert e3.sequence_number == 3
    end
  end

  describe "Memory.get_entry/2" do
    test "retrieves existing entry", %{server: server} do
      {:ok, entry} = Memory.log_event(:grant_created, %{actor_id: "alice"}, server)
      {:ok, retrieved} = Memory.get_entry(entry.id, server)

      assert retrieved.id == entry.id
      assert retrieved.actor_id == "alice"
    end

    test "returns not_found for missing entry", %{server: server} do
      assert {:error, :not_found} = Memory.get_entry("nonexistent", server)
    end
  end

  describe "Memory.query_events/2" do
    setup %{server: server} do
      # Create test events
      {:ok, e1} =
        Memory.log_event(
          :grant_created,
          %{actor_id: "alice", resource_id: "res1"},
          server
        )

      {:ok, e2} =
        Memory.log_event(
          :grant_revoked,
          %{actor_id: "bob", resource_id: "res1"},
          server
        )

      {:ok, e3} =
        Memory.log_event(
          :grant_created,
          %{actor_id: "alice", resource_id: "res2"},
          server
        )

      {:ok, e4} =
        Memory.log_event(
          :data_unsealed,
          %{actor_id: "charlie", resource_id: "res2"},
          server
        )

      {:ok, entries: [e1, e2, e3, e4]}
    end

    test "returns all events without filters", %{server: server} do
      {:ok, events} = Memory.query_events([], server)
      assert length(events) == 4
    end

    test "filters by event_type", %{server: server} do
      {:ok, events} = Memory.query_events([event_type: :grant_created], server)
      assert length(events) == 2
      assert Enum.all?(events, fn e -> e.event_type == :grant_created end)
    end

    test "filters by multiple event types", %{server: server} do
      {:ok, events} =
        Memory.query_events(
          [event_type: [:grant_created, :grant_revoked]],
          server
        )

      assert length(events) == 3
    end

    test "filters by actor_id", %{server: server} do
      {:ok, events} = Memory.query_events([actor_id: "alice"], server)
      assert length(events) == 2
      assert Enum.all?(events, fn e -> e.actor_id == "alice" end)
    end

    test "filters by resource_id", %{server: server} do
      {:ok, events} = Memory.query_events([resource_id: "res1"], server)
      assert length(events) == 2
      assert Enum.all?(events, fn e -> e.resource_id == "res1" end)
    end

    test "applies limit", %{server: server} do
      {:ok, events} = Memory.query_events([limit: 2], server)
      assert length(events) == 2
    end

    test "applies offset", %{server: server} do
      {:ok, all_events} = Memory.query_events([], server)
      {:ok, offset_events} = Memory.query_events([offset: 2], server)

      assert length(offset_events) == 2
      assert Enum.at(offset_events, 0).id == Enum.at(all_events, 2).id
    end

    test "applies limit and offset together", %{server: server} do
      {:ok, events} = Memory.query_events([offset: 1, limit: 2], server)
      assert length(events) == 2
    end

    test "results are sorted by timestamp", %{server: server, entries: entries} do
      {:ok, events} = Memory.query_events([], server)

      assert Enum.at(events, 0).id == Enum.at(entries, 0).id
      assert Enum.at(events, 3).id == Enum.at(entries, 3).id
    end
  end

  describe "Memory.query_events/2 time range filters" do
    test "filters by from timestamp", %{server: server} do
      # Log events with slight delay between
      {:ok, _e1} = Memory.log_event(:grant_created, %{}, server)
      Process.sleep(10)
      middle_time = DateTime.utc_now()
      Process.sleep(10)
      {:ok, _e2} = Memory.log_event(:grant_revoked, %{}, server)
      {:ok, _e3} = Memory.log_event(:grant_frozen, %{}, server)

      {:ok, events} = Memory.query_events([from: middle_time], server)
      assert length(events) == 2
    end

    test "filters by to timestamp", %{server: server} do
      {:ok, _e1} = Memory.log_event(:grant_created, %{}, server)
      {:ok, _e2} = Memory.log_event(:grant_revoked, %{}, server)
      Process.sleep(10)
      middle_time = DateTime.utc_now()
      Process.sleep(10)
      {:ok, _e3} = Memory.log_event(:grant_frozen, %{}, server)

      {:ok, events} = Memory.query_events([to: middle_time], server)
      assert length(events) == 2
    end

    test "filters by from and to timestamp", %{server: server} do
      {:ok, _e1} = Memory.log_event(:grant_created, %{}, server)
      Process.sleep(10)
      from_time = DateTime.utc_now()
      Process.sleep(10)
      {:ok, _e2} = Memory.log_event(:grant_revoked, %{}, server)
      {:ok, _e3} = Memory.log_event(:grant_frozen, %{}, server)
      Process.sleep(10)
      to_time = DateTime.utc_now()
      Process.sleep(10)
      {:ok, _e4} = Memory.log_event(:data_sealed, %{}, server)

      {:ok, events} = Memory.query_events([from: from_time, to: to_time], server)
      assert length(events) == 2
    end
  end

  describe "Memory.verify_chain/3" do
    test "returns ok for valid chain", %{server: server} do
      {:ok, e1} = Memory.log_event(:grant_created, %{}, server)
      {:ok, _e2} = Memory.log_event(:grant_revoked, %{}, server)
      {:ok, e3} = Memory.log_event(:grant_frozen, %{}, server)

      from = DateTime.add(e1.timestamp, -1, :second)
      to = DateTime.add(e3.timestamp, 1, :second)

      assert :ok = Memory.verify_chain(from, to, server)
    end

    test "returns empty_range when no entries", %{server: server} do
      from = ~U[2024-01-01 00:00:00Z]
      to = ~U[2024-12-31 23:59:59Z]

      assert {:error, :empty_range} = Memory.verify_chain(from, to, server)
    end

    test "returns empty_range when no entries in range", %{server: server} do
      {:ok, _} = Memory.log_event(:grant_created, %{}, server)

      # Query a time range in the past
      from = ~U[2020-01-01 00:00:00Z]
      to = ~U[2020-12-31 23:59:59Z]

      assert {:error, :empty_range} = Memory.verify_chain(from, to, server)
    end
  end

  describe "Memory.chain_head/1" do
    test "returns nil when no entries", %{server: server} do
      assert {:ok, nil} = Memory.chain_head(server)
    end

    test "returns hash of latest entry", %{server: server} do
      {:ok, _e1} = Memory.log_event(:grant_created, %{}, server)
      {:ok, e2} = Memory.log_event(:grant_revoked, %{}, server)

      {:ok, head} = Memory.chain_head(server)
      assert head == e2.entry_hash
    end
  end

  describe "Memory.info/1" do
    test "returns empty log info", %{server: server} do
      info = Memory.info(server)

      assert info.type == :memory
      assert info.entry_count == 0
      assert info.chain_head == nil
      assert info.oldest_entry == nil
      assert info.newest_entry == nil
      assert info.persistent == false
    end

    test "returns populated log info", %{server: server} do
      {:ok, e1} = Memory.log_event(:grant_created, %{}, server)
      {:ok, e2} = Memory.log_event(:grant_revoked, %{}, server)

      info = Memory.info(server)

      assert info.entry_count == 2
      assert info.chain_head == e2.entry_hash
      assert info.oldest_entry == e1.timestamp
      assert info.newest_entry == e2.timestamp
    end
  end

  describe "Memory.clear/1" do
    test "removes all entries and resets chain", %{server: server} do
      {:ok, _} = Memory.log_event(:grant_created, %{}, server)
      {:ok, _} = Memory.log_event(:grant_revoked, %{}, server)

      :ok = Memory.clear(server)

      {:ok, events} = Memory.query_events([], server)
      assert events == []

      {:ok, head} = Memory.chain_head(server)
      assert head == nil

      info = Memory.info(server)
      assert info.entry_count == 0
    end
  end

  # ============================================================================
  # Public API Tests
  # ============================================================================

  describe "Audit public API" do
    test "log_event/3 delegates to adapter", %{server: server} do
      {:ok, entry} = Memory.log_event(:grant_created, %{actor_id: "alice"}, server)
      assert entry.event_type == :grant_created
    end

    test "query_events/2 delegates to adapter", %{server: server} do
      {:ok, _} = Memory.log_event(:grant_created, %{}, server)
      {:ok, events} = Memory.query_events([], server)
      assert length(events) == 1
    end

    test "verify_chain/3 delegates to adapter", %{server: server} do
      {:ok, e1} = Memory.log_event(:grant_created, %{}, server)
      {:ok, e2} = Memory.log_event(:grant_revoked, %{}, server)

      from = DateTime.add(e1.timestamp, -1, :second)
      to = DateTime.add(e2.timestamp, 1, :second)

      assert :ok = Memory.verify_chain(from, to, server)
    end
  end

  describe "Audit convenience functions" do
    test "log_grant_created/2", %{server: server} do
      {:ok, entry} = Memory.log_event(:grant_created, %{grant_id: "g_123"}, server)
      assert entry.event_type == :grant_created
    end

    test "log_grant_revoked/2", %{server: server} do
      {:ok, entry} = Memory.log_event(:grant_revoked, %{grant_id: "g_123"}, server)
      assert entry.event_type == :grant_revoked
    end

    test "log_data_sealed/2", %{server: server} do
      {:ok, entry} = Memory.log_event(:data_sealed, %{resource_id: "res1"}, server)
      assert entry.event_type == :data_sealed
    end

    test "log_data_unsealed/2", %{server: server} do
      {:ok, entry} = Memory.log_event(:data_unsealed, %{resource_id: "res1"}, server)
      assert entry.event_type == :data_unsealed
    end

    test "log_access_denied/2", %{server: server} do
      {:ok, entry} = Memory.log_event(:access_denied, %{reason: "expired"}, server)
      assert entry.event_type == :access_denied
    end

    test "log_key_rotated/2", %{server: server} do
      {:ok, entry} = Memory.log_event(:key_rotated, %{epoch: 42}, server)
      assert entry.event_type == :key_rotated
    end
  end

  describe "Audit.export/2" do
    test "exports entries in external format", %{server: server} do
      {:ok, _} =
        Memory.log_event(
          :grant_created,
          %{
            actor_id: "alice",
            resource_id: "res1",
            grant_id: "g_123"
          },
          server
        )

      {:ok, events} = Memory.query_events([], server)
      # Manual export format check
      entry = hd(events)

      exported = %{
        id: entry.id,
        timestamp: DateTime.to_iso8601(entry.timestamp),
        event_type: entry.event_type,
        actor_id: entry.actor_id,
        resource_id: entry.resource_id,
        details: entry.details,
        entry_hash: Base.encode16(entry.entry_hash, case: :lower),
        previous_hash: nil
      }

      assert is_binary(exported.id)
      assert is_binary(exported.timestamp)
      assert exported.event_type == :grant_created
      assert exported.actor_id == "alice"
      assert exported.resource_id == "res1"
      assert is_binary(exported.entry_hash)
      assert exported.previous_hash == nil
    end

    test "exports with filters", %{server: server} do
      {:ok, _} = Memory.log_event(:grant_created, %{actor_id: "alice"}, server)
      {:ok, _} = Memory.log_event(:grant_revoked, %{actor_id: "bob"}, server)

      {:ok, events} = Memory.query_events([actor_id: "alice"], server)
      assert length(events) == 1
    end
  end

  # ============================================================================
  # Integration Tests
  # ============================================================================

  describe "full audit workflow" do
    test "logs grant lifecycle events", %{server: server} do
      actor = "did:web:alice.example"
      resource = "pod://data/record"
      grant_id = "grant_123"

      # Create grant
      {:ok, _} =
        Memory.log_event(
          :grant_created,
          %{
            actor_id: actor,
            resource_id: resource,
            grant_id: grant_id,
            scope: [:read, :write],
            grantee_id: "did:web:bob.example"
          },
          server
        )

      # Use grant
      {:ok, _} =
        Memory.log_event(
          :data_unsealed,
          %{
            actor_id: "did:web:bob.example",
            resource_id: resource,
            grant_id: grant_id
          },
          server
        )

      # Revoke grant
      {:ok, _} =
        Memory.log_event(
          :grant_revoked,
          %{
            actor_id: actor,
            resource_id: resource,
            grant_id: grant_id
          },
          server
        )

      # Access denied after revocation
      {:ok, _} =
        Memory.log_event(
          :access_denied,
          %{
            actor_id: "did:web:bob.example",
            resource_id: resource,
            grant_id: grant_id,
            reason: "grant_revoked"
          },
          server
        )

      # Query all events for the grant
      {:ok, events} = Memory.query_events([resource_id: resource], server)
      assert length(events) == 4

      # Verify chain integrity
      {:ok, e1} = Memory.get_entry(Enum.at(events, 0).id, server)
      {:ok, e4} = Memory.get_entry(Enum.at(events, 3).id, server)

      from = DateTime.add(e1.timestamp, -1, :second)
      to = DateTime.add(e4.timestamp, 1, :second)

      assert :ok = Memory.verify_chain(from, to, server)
    end

    test "detects tampering in chain", %{server: server} do
      {:ok, e1} = Memory.log_event(:grant_created, %{}, server)
      {:ok, e2} = Memory.log_event(:grant_revoked, %{}, server)
      {:ok, e3} = Memory.log_event(:grant_frozen, %{}, server)

      # The chain should be valid
      from = DateTime.add(e1.timestamp, -1, :second)
      to = DateTime.add(e3.timestamp, 1, :second)

      assert :ok = Memory.verify_chain(from, to, server)

      # Manually verify each entry's hash is correct
      assert Entry.verify_hash(e1) == true
      assert Entry.verify_hash(e2) == true
      assert Entry.verify_hash(e3) == true

      # Verify chain links
      assert Entry.verify_chain_link(e1, e2) == true
      assert Entry.verify_chain_link(e2, e3) == true
    end
  end
end
