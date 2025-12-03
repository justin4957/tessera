defmodule Tessera.Stores.Solid.ClientTest do
  use ExUnit.Case, async: true

  import Mox

  alias Tessera.Stores.Solid.Client

  setup :verify_on_exit!

  @pod_url "https://pod.test.example/alice"
  @token_endpoint "https://pod.test.example/.oidc/token"

  describe "create_session/3" do
    test "returns session on successful authentication" do
      # Mock OIDC discovery
      Tessera.MockHTTPClient
      |> expect(:get, fn url, _opts ->
        assert String.contains?(url, ".well-known/openid-configuration")

        {:ok,
         %{
           status: 200,
           body: %{"token_endpoint" => @token_endpoint},
           headers: []
         }}
      end)
      # Mock token request
      |> expect(:post, fn url, opts ->
        assert url == @token_endpoint
        assert Keyword.get(opts, :body) == "grant_type=client_credentials&scope=webid"

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

      credentials = %{id: "test-client-id", secret: "test-client-secret"}
      assert {:ok, session} = Client.create_session(@pod_url, credentials)

      assert session.access_token == "test-access-token"
      assert session.token_type == "Bearer"
      assert session.pod_url == @pod_url
      assert session.expires_at != nil
    end

    test "returns error on auth failure" do
      Tessera.MockHTTPClient
      |> expect(:get, fn _url, _opts ->
        {:ok,
         %{
           status: 200,
           body: %{"token_endpoint" => @token_endpoint},
           headers: []
         }}
      end)
      |> expect(:post, fn _url, _opts ->
        {:ok, %{status: 401, body: %{"error" => "invalid_client"}, headers: []}}
      end)

      credentials = %{id: "bad-id", secret: "bad-secret"}

      assert {:error, {:token_request_failed, 401, _}} =
               Client.create_session(@pod_url, credentials)
    end
  end

  describe "get_resource/3" do
    setup do
      session = %{
        access_token: "test-token",
        token_type: "Bearer",
        pod_url: @pod_url,
        expires_at: nil,
        webid: nil
      }

      {:ok, session: session}
    end

    test "retrieves a resource successfully", %{session: session} do
      Tessera.MockHTTPClient
      |> expect(:get, fn url, opts ->
        assert url == "#{@pod_url}/tessera/test.json"
        headers = Keyword.get(opts, :headers, [])
        assert {"authorization", "Bearer test-token"} in headers

        {:ok,
         %{
           status: 200,
           body: ~s({"data": "test-value"}),
           headers: [{"content-type", "application/json"}, {"etag", "\"abc123\""}]
         }}
      end)

      assert {:ok, body, metadata} = Client.get_resource(session, "tessera/test.json")
      assert body == ~s({"data": "test-value"})
      assert metadata.etag == "\"abc123\""
    end

    test "returns not_found for missing resource", %{session: session} do
      Tessera.MockHTTPClient
      |> expect(:get, fn _url, _opts ->
        {:ok, %{status: 404, body: "", headers: []}}
      end)

      assert {:error, :not_found} = Client.get_resource(session, "nonexistent.json")
    end

    test "returns unauthorized on 401", %{session: session} do
      Tessera.MockHTTPClient
      |> expect(:get, fn _url, _opts ->
        {:ok, %{status: 401, body: "", headers: []}}
      end)

      assert {:error, :unauthorized} = Client.get_resource(session, "protected.json")
    end
  end

  describe "put_resource/4" do
    setup do
      session = %{
        access_token: "test-token",
        token_type: "Bearer",
        pod_url: @pod_url,
        expires_at: nil,
        webid: nil
      }

      {:ok, session: session}
    end

    test "creates/updates a resource successfully", %{session: session} do
      Tessera.MockHTTPClient
      |> expect(:put, fn url, opts ->
        assert url == "#{@pod_url}/tessera/test.json"
        assert Keyword.get(opts, :body) == ~s({"data":"value"})
        headers = Keyword.get(opts, :headers, [])
        assert {"content-type", "application/json"} in headers

        {:ok,
         %{
           status: 201,
           body: "",
           headers: [{"etag", "\"new-etag\""}]
         }}
      end)

      assert {:ok, metadata} =
               Client.put_resource(session, "tessera/test.json", ~s({"data":"value"}))

      assert metadata.etag == "\"new-etag\""
    end

    test "returns forbidden on 403", %{session: session} do
      Tessera.MockHTTPClient
      |> expect(:put, fn _url, _opts ->
        {:ok, %{status: 403, body: "Forbidden", headers: []}}
      end)

      assert {:error, :forbidden} = Client.put_resource(session, "readonly.json", "data")
    end
  end

  describe "delete_resource/2" do
    setup do
      session = %{
        access_token: "test-token",
        token_type: "Bearer",
        pod_url: @pod_url,
        expires_at: nil,
        webid: nil
      }

      {:ok, session: session}
    end

    test "deletes a resource successfully", %{session: session} do
      Tessera.MockHTTPClient
      |> expect(:delete, fn url, _opts ->
        assert url == "#{@pod_url}/tessera/test.json"
        {:ok, %{status: 204, body: "", headers: []}}
      end)

      assert :ok = Client.delete_resource(session, "tessera/test.json")
    end

    test "returns not_found for missing resource", %{session: session} do
      Tessera.MockHTTPClient
      |> expect(:delete, fn _url, _opts ->
        {:ok, %{status: 404, body: "", headers: []}}
      end)

      assert {:error, :not_found} = Client.delete_resource(session, "nonexistent.json")
    end
  end

  describe "head_resource/2" do
    setup do
      session = %{
        access_token: "test-token",
        token_type: "Bearer",
        pod_url: @pod_url,
        expires_at: nil,
        webid: nil
      }

      {:ok, session: session}
    end

    test "returns metadata for existing resource", %{session: session} do
      Tessera.MockHTTPClient
      |> expect(:head, fn url, _opts ->
        assert url == "#{@pod_url}/tessera/test.json"

        {:ok,
         %{
           status: 200,
           body: "",
           headers: [{"etag", "\"abc\""}]
         }}
      end)

      assert {:ok, metadata} = Client.head_resource(session, "tessera/test.json")
      assert metadata.etag == "\"abc\""
    end

    test "returns not_found for missing resource", %{session: session} do
      Tessera.MockHTTPClient
      |> expect(:head, fn _url, _opts ->
        {:ok, %{status: 404, body: "", headers: []}}
      end)

      assert {:error, :not_found} = Client.head_resource(session, "nonexistent.json")
    end
  end

  describe "create_container/2" do
    setup do
      session = %{
        access_token: "test-token",
        token_type: "Bearer",
        pod_url: @pod_url,
        expires_at: nil,
        webid: nil
      }

      {:ok, session: session}
    end

    test "creates a container successfully", %{session: session} do
      Tessera.MockHTTPClient
      |> expect(:put, fn url, opts ->
        assert url == "#{@pod_url}/tessera/subdir/"
        headers = Keyword.get(opts, :headers, [])
        assert {"link", "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\""} in headers

        {:ok, %{status: 201, body: "", headers: []}}
      end)

      assert {:ok, _metadata} = Client.create_container(session, "tessera/subdir")
    end
  end

  describe "list_container/2" do
    setup do
      session = %{
        access_token: "test-token",
        token_type: "Bearer",
        pod_url: @pod_url,
        expires_at: nil,
        webid: nil
      }

      {:ok, session: session}
    end

    test "lists container contents", %{session: session} do
      container_response = """
      {
        "@context": {"ldp": "http://www.w3.org/ns/ldp#"},
        "@id": "#{@pod_url}/tessera/",
        "ldp:contains": [
          {"@id": "#{@pod_url}/tessera/file1.json"},
          {"@id": "#{@pod_url}/tessera/file2.json"}
        ]
      }
      """

      Tessera.MockHTTPClient
      |> expect(:get, fn url, _opts ->
        assert String.ends_with?(url, "/tessera/")

        {:ok,
         %{
           status: 200,
           body: container_response,
           headers: [{"content-type", "application/ld+json"}]
         }}
      end)

      assert {:ok, resources} = Client.list_container(session, "tessera")
      assert "#{@pod_url}/tessera/file1.json" in resources
      assert "#{@pod_url}/tessera/file2.json" in resources
    end
  end
end
