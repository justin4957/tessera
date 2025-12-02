defmodule Tessera.Stores.ATProto.AdapterTest do
  use ExUnit.Case, async: false

  import Mox

  alias Tessera.Stores.ATProto.Adapter

  # Use global mode since GenServer runs in a separate process
  setup :set_mox_global
  setup :verify_on_exit!

  @pds_url "https://test.pds.example"

  defp mock_successful_session do
    Tessera.MockHTTPClient
    |> expect(:post, fn url, _opts ->
      assert String.contains?(url, "createSession")

      {:ok,
       %{
         status: 200,
         body: %{
           "accessJwt" => "access-token",
           "refreshJwt" => "refresh-token",
           "did" => "did:plc:testuser123",
           "handle" => "test.user.example"
         }
       }}
    end)
  end

  describe "start_link/1" do
    test "starts adapter and authenticates with credentials" do
      mock_successful_session()

      assert {:ok, pid} =
               Adapter.start_link(
                 name: :test_atproto_auto,
                 pds_url: @pds_url,
                 identifier: "test.user.example",
                 password: "test-password"
               )

      assert Process.alive?(pid)

      # Clean up
      GenServer.stop(pid)
    end

    test "starts adapter without credentials (deferred auth)" do
      assert {:ok, pid} =
               Adapter.start_link(
                 name: :test_atproto_deferred,
                 pds_url: @pds_url
               )

      assert Process.alive?(pid)

      # Clean up
      GenServer.stop(pid)
    end
  end

  describe "put/4 and get/2" do
    setup do
      mock_successful_session()

      {:ok, pid} =
        Adapter.start_link(
          name: :test_atproto_put_get,
          pds_url: @pds_url,
          identifier: "test.user.example",
          password: "test-password"
        )

      on_exit(fn ->
        if Process.alive?(pid), do: GenServer.stop(pid)
      end)

      {:ok, server: :test_atproto_put_get}
    end

    test "stores and retrieves data", %{server: server} do
      # Mock put_record
      Tessera.MockHTTPClient
      |> expect(:post, fn url, opts ->
        assert String.contains?(url, "putRecord")
        assert opts[:json][:record]["data"] == %{"name" => "test-value"}

        {:ok, %{status: 200, body: %{"uri" => "at://did/collection/key"}}}
      end)

      # Mock get_record
      |> expect(:get, fn url, _opts ->
        assert String.contains?(url, "getRecord")

        {:ok,
         %{
           status: 200,
           body: %{
             "uri" => "at://did/collection/key",
             "value" => %{
               "resourceId" => "test/resource/1",
               "data" => %{"name" => "test-value"},
               "metadata" => %{},
               "createdAt" => "2024-01-01T00:00:00Z",
               "updatedAt" => "2024-01-01T00:00:00Z"
             }
           }
         }}
      end)

      assert :ok = Adapter.put("test/resource/1", %{"name" => "test-value"}, %{}, server)
      assert {:ok, data, _metadata} = Adapter.get("test/resource/1", server)
      assert data == %{"name" => "test-value"}
    end

    test "returns not_found for missing resource", %{server: server} do
      Tessera.MockHTTPClient
      |> expect(:get, fn _url, _opts ->
        {:ok, %{status: 400, body: %{"error" => "RecordNotFound"}}}
      end)

      assert {:error, :not_found} = Adapter.get("nonexistent", server)
    end
  end

  describe "delete/2" do
    setup do
      mock_successful_session()

      {:ok, pid} =
        Adapter.start_link(
          name: :test_atproto_delete,
          pds_url: @pds_url,
          identifier: "test.user.example",
          password: "test-password"
        )

      on_exit(fn ->
        if Process.alive?(pid), do: GenServer.stop(pid)
      end)

      {:ok, server: :test_atproto_delete}
    end

    test "deletes existing resource", %{server: server} do
      Tessera.MockHTTPClient
      |> expect(:post, fn url, _opts ->
        assert String.contains?(url, "deleteRecord")
        {:ok, %{status: 200, body: %{}}}
      end)

      assert :ok = Adapter.delete("test/resource/1", server)
    end

    test "returns not_found for missing resource", %{server: server} do
      Tessera.MockHTTPClient
      |> expect(:post, fn _url, _opts ->
        {:ok, %{status: 400, body: %{"error" => "RecordNotFound"}}}
      end)

      assert {:error, :not_found} = Adapter.delete("nonexistent", server)
    end
  end

  describe "list/2" do
    setup do
      mock_successful_session()

      {:ok, pid} =
        Adapter.start_link(
          name: :test_atproto_list,
          pds_url: @pds_url,
          identifier: "test.user.example",
          password: "test-password"
        )

      on_exit(fn ->
        if Process.alive?(pid), do: GenServer.stop(pid)
      end)

      {:ok, server: :test_atproto_list}
    end

    test "lists all resources", %{server: server} do
      Tessera.MockHTTPClient
      |> expect(:get, fn url, _opts ->
        assert String.contains?(url, "listRecords")

        {:ok,
         %{
           status: 200,
           body: %{
             "records" => [
               %{"value" => %{"resourceId" => "a/1"}},
               %{"value" => %{"resourceId" => "b/2"}},
               %{"value" => %{"resourceId" => "a/3"}}
             ]
           }
         }}
      end)

      assert {:ok, resources} = Adapter.list(nil, server)
      assert resources == ["a/1", "a/3", "b/2"]
    end

    test "filters by prefix", %{server: server} do
      Tessera.MockHTTPClient
      |> expect(:get, fn _url, _opts ->
        {:ok,
         %{
           status: 200,
           body: %{
             "records" => [
               %{"value" => %{"resourceId" => "users/1"}},
               %{"value" => %{"resourceId" => "posts/1"}},
               %{"value" => %{"resourceId" => "users/2"}}
             ]
           }
         }}
      end)

      assert {:ok, resources} = Adapter.list("users/", server)
      assert resources == ["users/1", "users/2"]
    end
  end

  describe "exists?/2" do
    setup do
      mock_successful_session()

      {:ok, pid} =
        Adapter.start_link(
          name: :test_atproto_exists,
          pds_url: @pds_url,
          identifier: "test.user.example",
          password: "test-password"
        )

      on_exit(fn ->
        if Process.alive?(pid), do: GenServer.stop(pid)
      end)

      {:ok, server: :test_atproto_exists}
    end

    test "returns true for existing resource", %{server: server} do
      Tessera.MockHTTPClient
      |> expect(:get, fn _url, _opts ->
        {:ok, %{status: 200, body: %{"value" => %{}}}}
      end)

      assert Adapter.exists?("test/resource", server) == true
    end

    test "returns false for missing resource", %{server: server} do
      Tessera.MockHTTPClient
      |> expect(:get, fn _url, _opts ->
        {:ok, %{status: 400, body: %{"error" => "RecordNotFound"}}}
      end)

      assert Adapter.exists?("nonexistent", server) == false
    end
  end

  describe "info/1" do
    setup do
      mock_successful_session()

      {:ok, pid} =
        Adapter.start_link(
          name: :test_atproto_info,
          pds_url: @pds_url,
          identifier: "test.user.example",
          password: "test-password"
        )

      on_exit(fn ->
        if Process.alive?(pid), do: GenServer.stop(pid)
      end)

      {:ok, server: :test_atproto_info}
    end

    test "returns adapter metadata", %{server: server} do
      info = Adapter.info(server)

      assert info.type == :atproto
      assert info.pds_url == @pds_url
      assert info.did == "did:plc:testuser123"
      assert info.handle == "test.user.example"
      assert info.connected == true
      assert info.persistent == true
      assert :read in info.capabilities
      assert :write in info.capabilities
    end
  end

  describe "connect/2" do
    test "connects with provided credentials" do
      {:ok, pid} = Adapter.start_link(name: :test_atproto_connect, pds_url: @pds_url)

      on_exit(fn ->
        if Process.alive?(pid), do: GenServer.stop(pid)
      end)

      # Initially not connected
      info = Adapter.info(:test_atproto_connect)
      assert info.connected == false

      # Mock the session creation
      mock_successful_session()

      # Connect
      assert :ok =
               Adapter.connect(
                 [identifier: "test.user.example", password: "test-password"],
                 :test_atproto_connect
               )

      # Now connected
      info = Adapter.info(:test_atproto_connect)
      assert info.connected == true
      assert info.did == "did:plc:testuser123"
    end
  end

  describe "disconnect/1" do
    test "disconnects and clears session" do
      mock_successful_session()

      {:ok, pid} =
        Adapter.start_link(
          name: :test_atproto_disconnect,
          pds_url: @pds_url,
          identifier: "test.user.example",
          password: "test-password"
        )

      on_exit(fn ->
        if Process.alive?(pid), do: GenServer.stop(pid)
      end)

      # Initially connected
      info = Adapter.info(:test_atproto_disconnect)
      assert info.connected == true

      # Disconnect
      assert :ok = Adapter.disconnect(:test_atproto_disconnect)

      # Now disconnected
      info = Adapter.info(:test_atproto_disconnect)
      assert info.connected == false
      assert info.did == nil
    end
  end
end
