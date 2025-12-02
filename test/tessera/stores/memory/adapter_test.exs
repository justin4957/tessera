defmodule Tessera.Stores.Memory.AdapterTest do
  use ExUnit.Case

  alias Tessera.Stores.Memory.Adapter

  setup do
    {:ok, pid} = Adapter.start_link(name: :test_store, table_name: :test_table)
    on_exit(fn -> Process.exit(pid, :kill) end)
    {:ok, store: :test_store}
  end

  describe "put/4 and get/2" do
    test "stores and retrieves data", %{store: store} do
      :ok = Adapter.put("resource/1", %{name: "test"}, %{}, store)
      {:ok, data, metadata} = Adapter.get("resource/1", store)

      assert data == %{name: "test"}
      assert %{created_at: _, updated_at: _} = metadata
    end

    test "returns not_found for missing resource", %{store: store} do
      assert {:error, :not_found} = Adapter.get("nonexistent", store)
    end
  end

  describe "delete/2" do
    test "removes existing resource", %{store: store} do
      :ok = Adapter.put("resource/1", %{}, %{}, store)
      :ok = Adapter.delete("resource/1", store)

      assert {:error, :not_found} = Adapter.get("resource/1", store)
    end

    test "returns not_found for missing resource", %{store: store} do
      assert {:error, :not_found} = Adapter.delete("nonexistent", store)
    end
  end

  describe "list/2" do
    test "lists all resources", %{store: store} do
      :ok = Adapter.put("a/1", %{}, %{}, store)
      :ok = Adapter.put("b/2", %{}, %{}, store)
      :ok = Adapter.put("a/3", %{}, %{}, store)

      {:ok, resources} = Adapter.list(nil, store)
      assert resources == ["a/1", "a/3", "b/2"]
    end

    test "filters by prefix", %{store: store} do
      :ok = Adapter.put("users/1", %{}, %{}, store)
      :ok = Adapter.put("users/2", %{}, %{}, store)
      :ok = Adapter.put("posts/1", %{}, %{}, store)

      {:ok, resources} = Adapter.list("users/", store)
      assert resources == ["users/1", "users/2"]
    end
  end

  describe "exists?/2" do
    test "returns true for existing resource", %{store: store} do
      :ok = Adapter.put("resource/1", %{}, %{}, store)
      assert Adapter.exists?("resource/1", store) == true
    end

    test "returns false for missing resource", %{store: store} do
      assert Adapter.exists?("nonexistent", store) == false
    end
  end

  describe "info/1" do
    test "returns store metadata", %{store: store} do
      info = Adapter.info(store)

      assert info.type == :memory
      assert info.persistent == false
      assert :read in info.capabilities
    end
  end
end
