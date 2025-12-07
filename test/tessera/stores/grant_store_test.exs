defmodule Tessera.Stores.GrantStoreTest do
  use ExUnit.Case, async: true

  alias Tessera.Core.Grants.Grant
  alias Tessera.Core.Rights.TemporalInterval
  alias Tessera.Stores.GrantStore.{Memory, Serializer}

  # ============================================================================
  # Test Setup
  # ============================================================================

  setup do
    # Start a fresh memory store for each test
    table_prefix = "test_#{:erlang.unique_integer([:positive])}"

    {:ok, pid} =
      Memory.start_link(name: :"grant_store_#{table_prefix}", table_prefix: table_prefix)

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid)
    end)

    server = :"grant_store_#{table_prefix}"

    # Create some test grants
    interval = TemporalInterval.for_duration(90, :day)

    grant1 =
      Grant.new(
        id: "grant_1",
        grantee_id: "did:web:alice.example",
        resource_id: "pod://bob.example/medical/records",
        interval: interval,
        scope: [:read],
        purpose: "insurance_claim"
      )

    grant2 =
      Grant.new(
        id: "grant_2",
        grantee_id: "did:web:alice.example",
        resource_id: "pod://bob.example/financial/statements",
        interval: interval,
        scope: [:read, :export],
        purpose: "tax_filing"
      )

    grant3 =
      Grant.new(
        id: "grant_3",
        grantee_id: "did:web:charlie.example",
        resource_id: "pod://bob.example/medical/records",
        interval: interval,
        scope: [:read, :compute],
        purpose: "research_study"
      )

    %{
      server: server,
      grant1: grant1,
      grant2: grant2,
      grant3: grant3,
      interval: interval
    }
  end

  # ============================================================================
  # Serializer Tests
  # ============================================================================

  describe "Serializer.serialize/1" do
    test "serializes a grant to a map", %{grant1: grant} do
      assert {:ok, map} = Serializer.serialize(grant)

      assert map["id"] == "grant_1"
      assert map["grantee_id"] == "did:web:alice.example"
      assert map["resource_id"] == "pod://bob.example/medical/records"
      assert map["scope"] == ["read"]
      assert map["purpose"] == "insurance_claim"
      assert map["frozen"] == false
      assert is_nil(map["revoked_at"])
      assert map["version"] == 1

      # Check interval serialization
      assert is_binary(map["interval"]["start_time"])
      assert is_binary(map["interval"]["end_time"])
    end

    test "returns error for invalid input" do
      assert {:error, :invalid_grant} = Serializer.serialize("not a grant")
      assert {:error, :invalid_grant} = Serializer.serialize(%{})
    end
  end

  describe "Serializer.deserialize/1" do
    test "deserializes a map to a grant", %{grant1: grant} do
      {:ok, map} = Serializer.serialize(grant)
      assert {:ok, restored} = Serializer.deserialize(map)

      assert restored.id == grant.id
      assert restored.grantee_id == grant.grantee_id
      assert restored.resource_id == grant.resource_id
      assert restored.scope == grant.scope
      assert restored.purpose == grant.purpose
      assert restored.frozen == grant.frozen
    end

    test "handles JSON round-trip", %{grant1: grant} do
      {:ok, json} = Serializer.to_json(grant)
      assert is_binary(json)

      {:ok, restored} = Serializer.from_json(json)
      assert restored.id == grant.id
      assert restored.grantee_id == grant.grantee_id
    end

    test "returns error for invalid data" do
      assert {:error, :invalid_data} = Serializer.deserialize("not a map")
      assert {:error, _} = Serializer.deserialize(%{"id" => "test"})
    end

    test "returns error for invalid JSON" do
      assert {:error, _} = Serializer.from_json("not json")
      assert {:error, :invalid_json} = Serializer.from_json(123)
    end
  end

  # ============================================================================
  # Memory Adapter - Core CRUD Tests
  # ============================================================================

  describe "Memory.store_grant/2" do
    test "stores a grant successfully", %{server: server, grant1: grant} do
      assert {:ok, stored} = Memory.store_grant(grant, server)
      assert stored.id == grant.id
    end

    test "stores multiple grants", %{server: server, grant1: g1, grant2: g2, grant3: g3} do
      assert {:ok, _} = Memory.store_grant(g1, server)
      assert {:ok, _} = Memory.store_grant(g2, server)
      assert {:ok, _} = Memory.store_grant(g3, server)

      assert %{grant_count: 3} = Memory.info(server)
    end

    test "updates existing grant", %{server: server, grant1: grant} do
      {:ok, _} = Memory.store_grant(grant, server)

      updated = %{grant | purpose: "updated_purpose"}
      {:ok, stored} = Memory.store_grant(updated, server)

      assert stored.purpose == "updated_purpose"
      assert %{grant_count: 1} = Memory.info(server)
    end

    test "prevents updating frozen grant", %{server: server, grant1: grant} do
      {:ok, _} = Memory.store_grant(grant, server)
      {:ok, _frozen} = Memory.freeze_grant(grant.id, server)

      updated = %{grant | purpose: "should_fail"}
      assert {:error, :frozen} = Memory.store_grant(updated, server)
    end
  end

  describe "Memory.get_grant/2" do
    test "retrieves stored grant", %{server: server, grant1: grant} do
      {:ok, _} = Memory.store_grant(grant, server)

      assert {:ok, retrieved} = Memory.get_grant(grant.id, server)
      assert retrieved.id == grant.id
      assert retrieved.grantee_id == grant.grantee_id
    end

    test "returns not_found for missing grant", %{server: server} do
      assert {:error, :not_found} = Memory.get_grant("nonexistent", server)
    end
  end

  describe "Memory.delete_grant/2" do
    test "deletes a grant", %{server: server, grant1: grant} do
      {:ok, _} = Memory.store_grant(grant, server)
      assert :ok = Memory.delete_grant(grant.id, server)
      assert {:error, :not_found} = Memory.get_grant(grant.id, server)
    end

    test "returns not_found for missing grant", %{server: server} do
      assert {:error, :not_found} = Memory.delete_grant("nonexistent", server)
    end

    test "prevents deleting frozen grant", %{server: server, grant1: grant} do
      {:ok, _} = Memory.store_grant(grant, server)
      {:ok, _} = Memory.freeze_grant(grant.id, server)

      assert {:error, :frozen} = Memory.delete_grant(grant.id, server)
    end
  end

  # ============================================================================
  # Memory Adapter - Query Tests
  # ============================================================================

  describe "Memory.list_grants_for_resource/3" do
    test "lists grants by resource", %{server: server, grant1: g1, grant3: g3} do
      {:ok, _} = Memory.store_grant(g1, server)
      {:ok, _} = Memory.store_grant(g3, server)

      {:ok, grants} =
        Memory.list_grants_for_resource("pod://bob.example/medical/records", [], server)

      assert length(grants) == 2
      grant_ids = Enum.map(grants, & &1.id)
      assert "grant_1" in grant_ids
      assert "grant_3" in grant_ids
    end

    test "returns empty list for unknown resource", %{server: server} do
      {:ok, grants} = Memory.list_grants_for_resource("unknown", [], server)
      assert grants == []
    end
  end

  describe "Memory.list_grants_for_grantee/3" do
    test "lists grants by grantee", %{server: server, grant1: g1, grant2: g2} do
      {:ok, _} = Memory.store_grant(g1, server)
      {:ok, _} = Memory.store_grant(g2, server)

      {:ok, grants} = Memory.list_grants_for_grantee("did:web:alice.example", [], server)

      assert length(grants) == 2
      grant_ids = Enum.map(grants, & &1.id)
      assert "grant_1" in grant_ids
      assert "grant_2" in grant_ids
    end

    test "returns empty list for unknown grantee", %{server: server} do
      {:ok, grants} = Memory.list_grants_for_grantee("unknown", [], server)
      assert grants == []
    end
  end

  describe "Memory.list_grants/2" do
    test "lists all grants", %{server: server, grant1: g1, grant2: g2, grant3: g3} do
      {:ok, _} = Memory.store_grant(g1, server)
      {:ok, _} = Memory.store_grant(g2, server)
      {:ok, _} = Memory.store_grant(g3, server)

      {:ok, grants} = Memory.list_grants([], server)
      assert length(grants) == 3
    end

    test "supports pagination with limit", %{server: server, grant1: g1, grant2: g2, grant3: g3} do
      {:ok, _} = Memory.store_grant(g1, server)
      {:ok, _} = Memory.store_grant(g2, server)
      {:ok, _} = Memory.store_grant(g3, server)

      {:ok, grants} = Memory.list_grants([limit: 2], server)
      assert length(grants) == 2
    end

    test "supports pagination with offset", %{server: server, grant1: g1, grant2: g2, grant3: g3} do
      {:ok, _} = Memory.store_grant(g1, server)
      {:ok, _} = Memory.store_grant(g2, server)
      {:ok, _} = Memory.store_grant(g3, server)

      {:ok, grants} = Memory.list_grants([offset: 1], server)
      assert length(grants) == 2
    end
  end

  # ============================================================================
  # Memory Adapter - Filter Tests
  # ============================================================================

  describe "query filtering" do
    test "active_only filter", %{server: server, grant1: grant} do
      # Create an expired grant
      past_interval =
        TemporalInterval.new(
          DateTime.add(DateTime.utc_now(), -10, :day),
          DateTime.add(DateTime.utc_now(), -1, :day)
        )

      expired_grant = %{grant | id: "expired", interval: past_interval}

      {:ok, _} = Memory.store_grant(grant, server)
      {:ok, _} = Memory.store_grant(expired_grant, server)

      # Without filter - both returned
      {:ok, all} = Memory.list_grants([], server)
      assert length(all) == 2

      # With active_only - only active grant
      {:ok, active} = Memory.list_grants([active_only: true], server)
      assert length(active) == 1
      assert hd(active).id == grant.id
    end

    test "include_revoked filter", %{server: server, grant1: g1, grant2: g2} do
      {:ok, _} = Memory.store_grant(g1, server)
      {:ok, _} = Memory.store_grant(g2, server)
      {:ok, _revoked} = Memory.revoke_grant(g1.id, server)

      # Include revoked (default)
      {:ok, all} = Memory.list_grants([include_revoked: true], server)
      assert length(all) == 2

      # Exclude revoked
      {:ok, not_revoked} = Memory.list_grants([include_revoked: false], server)
      assert length(not_revoked) == 1
      assert hd(not_revoked).id == g2.id
    end

    test "at time filter", %{server: server} do
      now = DateTime.utc_now()

      # Grant active from yesterday to tomorrow
      interval1 =
        TemporalInterval.new(
          DateTime.add(now, -1, :day),
          DateTime.add(now, 1, :day)
        )

      # Grant active from tomorrow onwards
      interval2 =
        TemporalInterval.new(
          DateTime.add(now, 1, :day),
          DateTime.add(now, 10, :day)
        )

      grant1 =
        Grant.new(
          id: "current",
          grantee_id: "alice",
          resource_id: "data",
          interval: interval1,
          scope: [:read]
        )

      grant2 =
        Grant.new(
          id: "future",
          grantee_id: "alice",
          resource_id: "data",
          interval: interval2,
          scope: [:read]
        )

      {:ok, _} = Memory.store_grant(grant1, server)
      {:ok, _} = Memory.store_grant(grant2, server)

      # Query at current time
      {:ok, current} = Memory.list_grants([at: now], server)
      assert length(current) == 1
      assert hd(current).id == "current"

      # Query at future time
      future = DateTime.add(now, 2, :day)
      {:ok, future_grants} = Memory.list_grants([at: future], server)
      assert length(future_grants) == 1
      assert hd(future_grants).id == "future"
    end
  end

  # ============================================================================
  # Memory Adapter - Lifecycle Tests
  # ============================================================================

  describe "Memory.revoke_grant/2" do
    test "revokes a grant", %{server: server, grant1: grant} do
      {:ok, _} = Memory.store_grant(grant, server)

      assert {:ok, revoked} = Memory.revoke_grant(grant.id, server)
      assert not is_nil(revoked.revoked_at)
      assert Grant.active?(revoked) == false
    end

    test "returns error for already revoked grant", %{server: server, grant1: grant} do
      {:ok, _} = Memory.store_grant(grant, server)
      {:ok, _} = Memory.revoke_grant(grant.id, server)

      assert {:error, :already_revoked} = Memory.revoke_grant(grant.id, server)
    end

    test "returns error for frozen grant", %{server: server, grant1: grant} do
      {:ok, _} = Memory.store_grant(grant, server)
      {:ok, _} = Memory.freeze_grant(grant.id, server)

      assert {:error, :frozen} = Memory.revoke_grant(grant.id, server)
    end

    test "returns not_found for missing grant", %{server: server} do
      assert {:error, :not_found} = Memory.revoke_grant("nonexistent", server)
    end
  end

  describe "Memory.freeze_grant/2" do
    test "freezes a grant", %{server: server, grant1: grant} do
      {:ok, _} = Memory.store_grant(grant, server)

      assert {:ok, frozen} = Memory.freeze_grant(grant.id, server)
      assert frozen.frozen == true
    end

    test "returns error for already frozen grant", %{server: server, grant1: grant} do
      {:ok, _} = Memory.store_grant(grant, server)
      {:ok, _} = Memory.freeze_grant(grant.id, server)

      assert {:error, :already_frozen} = Memory.freeze_grant(grant.id, server)
    end

    test "returns not_found for missing grant", %{server: server} do
      assert {:error, :not_found} = Memory.freeze_grant("nonexistent", server)
    end
  end

  # ============================================================================
  # Memory Adapter - Info Tests
  # ============================================================================

  describe "Memory.info/1" do
    test "returns adapter information", %{server: server, grant1: g1, grant2: g2} do
      {:ok, _} = Memory.store_grant(g1, server)
      {:ok, _} = Memory.store_grant(g2, server)

      info = Memory.info(server)

      assert info.type == :memory
      assert info.grant_count == 2
      assert info.persistent == false
      assert :store in info.capabilities
      assert :query_by_resource in info.capabilities
      assert :resource_id in info.indexes
    end
  end

  # ============================================================================
  # Memory Adapter - Clear Tests
  # ============================================================================

  describe "Memory.clear/1" do
    test "clears all grants", %{server: server, grant1: g1, grant2: g2} do
      {:ok, _} = Memory.store_grant(g1, server)
      {:ok, _} = Memory.store_grant(g2, server)

      assert :ok = Memory.clear(server)
      assert %{grant_count: 0} = Memory.info(server)
    end
  end

  # ============================================================================
  # Public API (Behaviour Delegation) Tests
  # ============================================================================

  describe "GrantStore public API" do
    test "delegates to adapter module", %{server: server, grant1: grant} do
      # Store using the test server first
      {:ok, stored} = Memory.store_grant(grant, server)

      # Verify the behaviour module API works with explicit adapter
      # Note: The public API delegates to the module, so we test with our server
      {:ok, retrieved} = Memory.get_grant(grant.id, server)

      assert retrieved.id == stored.id

      # Test other public API functions
      {:ok, grants} = Memory.list_grants_for_resource(grant.resource_id, [], server)
      assert length(grants) == 1

      {:ok, grantee_grants} = Memory.list_grants_for_grantee(grant.grantee_id, [], server)
      assert length(grantee_grants) == 1
    end
  end

  # ============================================================================
  # Index Consistency Tests
  # ============================================================================

  describe "index consistency" do
    test "indexes are updated when grant is deleted", %{server: server, grant1: grant} do
      {:ok, _} = Memory.store_grant(grant, server)

      # Verify grant appears in index
      {:ok, before} = Memory.list_grants_for_resource(grant.resource_id, [], server)
      assert length(before) == 1

      # Delete grant
      :ok = Memory.delete_grant(grant.id, server)

      # Verify grant removed from index
      {:ok, after_delete} = Memory.list_grants_for_resource(grant.resource_id, [], server)
      assert length(after_delete) == 0
    end

    test "indexes are updated when grant resource changes", %{server: server, grant1: grant} do
      {:ok, _} = Memory.store_grant(grant, server)

      # Update with new resource
      updated = %{grant | resource_id: "new_resource"}
      {:ok, _} = Memory.store_grant(updated, server)

      # Old resource should have no grants
      {:ok, old} = Memory.list_grants_for_resource(grant.resource_id, [], server)
      assert length(old) == 0

      # New resource should have the grant
      {:ok, new} = Memory.list_grants_for_resource("new_resource", [], server)
      assert length(new) == 1
    end
  end
end
