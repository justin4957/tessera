defmodule Tessera.Stores.Solid.AdapterTest do
  use ExUnit.Case, async: false

  import Mox

  alias Tessera.Stores.Solid.Adapter

  # Use global mode since GenServer runs in a separate process
  setup :set_mox_global
  setup :verify_on_exit!

  @pod_url "https://pod.test.example/alice"
  @token_endpoint "https://pod.test.example/.oidc/token"

  defp mock_successful_session do
    # Mock OIDC discovery
    Tessera.MockHTTPClient
    |> expect(:get, fn url, _opts ->
      if String.contains?(url, ".well-known") do
        {:ok,
         %{
           status: 200,
           body: %{"token_endpoint" => @token_endpoint},
           headers: []
         }}
      else
        {:ok, %{status: 404, body: "", headers: []}}
      end
    end)
    # Mock token request
    |> expect(:post, fn url, _opts ->
      assert String.contains?(url, "token")

      {:ok,
       %{
         status: 200,
         body: %{
           "access_token" => "test-access-token",
           "token_type" => "Bearer",
           "expires_in" => 3600
         },
         headers: []
       }}
    end)
  end

  describe "start_link/1" do
    test "starts adapter and authenticates with credentials" do
      mock_successful_session()

      assert {:ok, pid} =
               Adapter.start_link(
                 name: :test_solid_auto,
                 pod_url: @pod_url,
                 credentials: %{id: "test-id", secret: "test-secret"}
               )

      assert Process.alive?(pid)
      GenServer.stop(pid)
    end

    test "starts adapter without credentials (deferred auth)" do
      assert {:ok, pid} =
               Adapter.start_link(
                 name: :test_solid_deferred,
                 pod_url: @pod_url
               )

      assert Process.alive?(pid)
      GenServer.stop(pid)
    end
  end

  describe "put/4 and get/2" do
    setup do
      mock_successful_session()

      {:ok, pid} =
        Adapter.start_link(
          name: :test_solid_put_get,
          pod_url: @pod_url,
          credentials: %{id: "test-id", secret: "test-secret"}
        )

      on_exit(fn ->
        if Process.alive?(pid), do: GenServer.stop(pid)
      end)

      {:ok, server: :test_solid_put_get}
    end

    test "stores and retrieves data", %{server: server} do
      # Mock container creation (tessera/ and tessera/test/)
      Tessera.MockHTTPClient
      |> expect(:put, 2, fn url, _opts ->
        # Container creation calls
        assert String.ends_with?(url, "/")
        {:ok, %{status: 201, body: "", headers: []}}
      end)
      # Mock resource PUT
      |> expect(:put, fn url, _opts ->
        refute String.ends_with?(url, "/")
        {:ok, %{status: 201, body: "", headers: [{"etag", "\"123\""}]}}
      end)
      # Mock get_resource
      |> expect(:get, fn _url, _opts ->
        {:ok,
         %{
           status: 200,
           body:
             Jason.encode!(%{
               "resourceId" => "test/resource",
               "data" => %{"name" => "test-value"},
               "metadata" => %{},
               "createdAt" => "2024-01-01T00:00:00Z",
               "updatedAt" => "2024-01-01T00:00:00Z"
             }),
           headers: [{"content-type", "application/json"}]
         }}
      end)

      assert :ok = Adapter.put("test/resource", %{"name" => "test-value"}, %{}, server)
      assert {:ok, data, _metadata} = Adapter.get("test/resource", server)
      assert data == %{"name" => "test-value"}
    end

    test "returns not_found for missing resource", %{server: server} do
      Tessera.MockHTTPClient
      |> expect(:get, fn _url, _opts ->
        {:ok, %{status: 404, body: "", headers: []}}
      end)

      assert {:error, :not_found} = Adapter.get("nonexistent", server)
    end
  end

  describe "delete/2" do
    setup do
      mock_successful_session()

      {:ok, pid} =
        Adapter.start_link(
          name: :test_solid_delete,
          pod_url: @pod_url,
          credentials: %{id: "test-id", secret: "test-secret"}
        )

      on_exit(fn ->
        if Process.alive?(pid), do: GenServer.stop(pid)
      end)

      {:ok, server: :test_solid_delete}
    end

    test "deletes existing resource", %{server: server} do
      Tessera.MockHTTPClient
      |> expect(:delete, fn _url, _opts ->
        {:ok, %{status: 204, body: "", headers: []}}
      end)

      assert :ok = Adapter.delete("test/resource", server)
    end

    test "returns not_found for missing resource", %{server: server} do
      Tessera.MockHTTPClient
      |> expect(:delete, fn _url, _opts ->
        {:ok, %{status: 404, body: "", headers: []}}
      end)

      assert {:error, :not_found} = Adapter.delete("nonexistent", server)
    end
  end

  describe "list/2" do
    setup do
      mock_successful_session()

      {:ok, pid} =
        Adapter.start_link(
          name: :test_solid_list,
          pod_url: @pod_url,
          credentials: %{id: "test-id", secret: "test-secret"}
        )

      on_exit(fn ->
        if Process.alive?(pid), do: GenServer.stop(pid)
      end)

      {:ok, server: :test_solid_list}
    end

    test "lists all resources", %{server: server} do
      container_response =
        Jason.encode!(%{
          "ldp:contains" => [
            %{"@id" => "#{@pod_url}/tessera/a_1.json"},
            %{"@id" => "#{@pod_url}/tessera/b_2.json"},
            %{"@id" => "#{@pod_url}/tessera/a_3.json"}
          ]
        })

      Tessera.MockHTTPClient
      |> expect(:get, fn _url, _opts ->
        {:ok,
         %{
           status: 200,
           body: container_response,
           headers: [{"content-type", "application/ld+json"}]
         }}
      end)

      assert {:ok, resources} = Adapter.list(nil, server)
      assert "a_1" in resources
      assert "a_3" in resources
      assert "b_2" in resources
    end

    test "filters by prefix", %{server: server} do
      container_response =
        Jason.encode!(%{
          "ldp:contains" => [
            %{"@id" => "#{@pod_url}/tessera/users_1.json"},
            %{"@id" => "#{@pod_url}/tessera/posts_1.json"},
            %{"@id" => "#{@pod_url}/tessera/users_2.json"}
          ]
        })

      Tessera.MockHTTPClient
      |> expect(:get, fn _url, _opts ->
        {:ok,
         %{
           status: 200,
           body: container_response,
           headers: [{"content-type", "application/ld+json"}]
         }}
      end)

      assert {:ok, resources} = Adapter.list("users", server)
      assert "users_1" in resources
      assert "users_2" in resources
      refute "posts_1" in resources
    end
  end

  describe "exists?/2" do
    setup do
      mock_successful_session()

      {:ok, pid} =
        Adapter.start_link(
          name: :test_solid_exists,
          pod_url: @pod_url,
          credentials: %{id: "test-id", secret: "test-secret"}
        )

      on_exit(fn ->
        if Process.alive?(pid), do: GenServer.stop(pid)
      end)

      {:ok, server: :test_solid_exists}
    end

    test "returns true for existing resource", %{server: server} do
      Tessera.MockHTTPClient
      |> expect(:head, fn _url, _opts ->
        {:ok, %{status: 200, body: "", headers: [{"etag", "\"abc\""}]}}
      end)

      assert Adapter.exists?("test/resource", server) == true
    end

    test "returns false for missing resource", %{server: server} do
      Tessera.MockHTTPClient
      |> expect(:head, fn _url, _opts ->
        {:ok, %{status: 404, body: "", headers: []}}
      end)

      assert Adapter.exists?("nonexistent", server) == false
    end
  end

  describe "info/1" do
    setup do
      mock_successful_session()

      {:ok, pid} =
        Adapter.start_link(
          name: :test_solid_info,
          pod_url: @pod_url,
          credentials: %{id: "test-id", secret: "test-secret"}
        )

      on_exit(fn ->
        if Process.alive?(pid), do: GenServer.stop(pid)
      end)

      {:ok, server: :test_solid_info}
    end

    test "returns adapter metadata", %{server: server} do
      info = Adapter.info(server)

      assert info.type == :solid
      assert info.pod_url == @pod_url
      assert info.base_path == "tessera/"
      assert info.connected == true
      assert info.persistent == true
      assert :read in info.capabilities
      assert :write in info.capabilities
    end
  end

  describe "connect/2" do
    test "connects with provided credentials" do
      {:ok, pid} = Adapter.start_link(name: :test_solid_connect, pod_url: @pod_url)

      on_exit(fn ->
        if Process.alive?(pid), do: GenServer.stop(pid)
      end)

      # Initially not connected
      info = Adapter.info(:test_solid_connect)
      assert info.connected == false

      # Mock the session creation
      mock_successful_session()

      # Connect
      assert :ok =
               Adapter.connect(
                 [credentials: %{id: "test-id", secret: "test-secret"}],
                 :test_solid_connect
               )

      # Now connected
      info = Adapter.info(:test_solid_connect)
      assert info.connected == true
    end
  end

  describe "disconnect/1" do
    test "disconnects and clears session" do
      mock_successful_session()

      {:ok, pid} =
        Adapter.start_link(
          name: :test_solid_disconnect,
          pod_url: @pod_url,
          credentials: %{id: "test-id", secret: "test-secret"}
        )

      on_exit(fn ->
        if Process.alive?(pid), do: GenServer.stop(pid)
      end)

      # Initially connected
      info = Adapter.info(:test_solid_disconnect)
      assert info.connected == true

      # Disconnect
      assert :ok = Adapter.disconnect(:test_solid_disconnect)

      # Now disconnected
      info = Adapter.info(:test_solid_disconnect)
      assert info.connected == false
    end
  end
end
