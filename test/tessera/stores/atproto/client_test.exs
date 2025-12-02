defmodule Tessera.Stores.ATProto.ClientTest do
  use ExUnit.Case, async: true

  import Mox

  alias Tessera.Stores.ATProto.Client

  setup :verify_on_exit!

  @pds_url "https://test.pds.example"

  describe "create_session/3" do
    test "returns session on successful authentication" do
      Tessera.MockHTTPClient
      |> expect(:post, fn url, opts ->
        assert url == "#{@pds_url}/xrpc/com.atproto.server.createSession"
        assert opts[:json] == %{identifier: "test.user", password: "test-password"}

        {:ok,
         %{
           status: 200,
           body: %{
             "accessJwt" => "access-token",
             "refreshJwt" => "refresh-token",
             "did" => "did:plc:abc123",
             "handle" => "test.user"
           }
         }}
      end)

      assert {:ok, session} =
               Client.create_session("test.user", "test-password", pds_url: @pds_url)

      assert session.access_jwt == "access-token"
      assert session.refresh_jwt == "refresh-token"
      assert session.did == "did:plc:abc123"
      assert session.handle == "test.user"
    end

    test "returns error on auth failure" do
      Tessera.MockHTTPClient
      |> expect(:post, fn _url, _opts ->
        {:ok, %{status: 401, body: %{"error" => "AuthenticationRequired"}}}
      end)

      assert {:error, {:auth_failed, 401, _}} =
               Client.create_session("test.user", "wrong-password", pds_url: @pds_url)
    end

    test "returns error on network failure" do
      Tessera.MockHTTPClient
      |> expect(:post, fn _url, _opts ->
        {:error, %Mint.TransportError{reason: :timeout}}
      end)

      assert {:error, {:network_error, _}} =
               Client.create_session("test.user", "test-password", pds_url: @pds_url)
    end
  end

  describe "put_record/4" do
    setup do
      session = %{
        access_jwt: "test-token",
        refresh_jwt: "refresh-token",
        did: "did:plc:abc123",
        handle: "test.user"
      }

      {:ok, session: session}
    end

    test "creates/updates a record successfully", %{session: session} do
      Tessera.MockHTTPClient
      |> expect(:post, fn url, opts ->
        assert url == "#{@pds_url}/xrpc/com.atproto.repo.putRecord"
        assert opts[:auth] == {:bearer, "test-token"}
        assert opts[:json][:repo] == "did:plc:abc123"
        assert opts[:json][:rkey] == "test-key"
        assert opts[:json][:record]["$type"] == "app.tessera.store.record"

        {:ok,
         %{status: 200, body: %{"uri" => "at://did:plc:abc123/app.tessera.store.record/test-key"}}}
      end)

      assert {:ok, response} =
               Client.put_record(session, "test-key", %{data: "value"}, pds_url: @pds_url)

      assert response["uri"] =~ "test-key"
    end
  end

  describe "get_record/4" do
    setup do
      session = %{
        access_jwt: "test-token",
        refresh_jwt: "refresh-token",
        did: "did:plc:abc123",
        handle: "test.user"
      }

      {:ok, session: session}
    end

    test "retrieves a record successfully", %{session: session} do
      Tessera.MockHTTPClient
      |> expect(:get, fn url, opts ->
        assert url == "#{@pds_url}/xrpc/com.atproto.repo.getRecord"
        assert opts[:params][:repo] == "did:plc:abc123"
        assert opts[:params][:rkey] == "test-key"

        {:ok,
         %{
           status: 200,
           body: %{
             "uri" => "at://did:plc:abc123/app.tessera.store.record/test-key",
             "value" => %{"data" => "value"}
           }
         }}
      end)

      assert {:ok, record} =
               Client.get_record(session, "did:plc:abc123", "test-key", pds_url: @pds_url)

      assert record["value"]["data"] == "value"
    end

    test "returns not_found for missing record", %{session: session} do
      Tessera.MockHTTPClient
      |> expect(:get, fn _url, _opts ->
        {:ok, %{status: 400, body: %{"error" => "RecordNotFound"}}}
      end)

      assert {:error, :not_found} =
               Client.get_record(session, "did:plc:abc123", "missing-key", pds_url: @pds_url)
    end
  end

  describe "delete_record/3" do
    setup do
      session = %{
        access_jwt: "test-token",
        refresh_jwt: "refresh-token",
        did: "did:plc:abc123",
        handle: "test.user"
      }

      {:ok, session: session}
    end

    test "deletes a record successfully", %{session: session} do
      Tessera.MockHTTPClient
      |> expect(:post, fn url, opts ->
        assert url == "#{@pds_url}/xrpc/com.atproto.repo.deleteRecord"
        assert opts[:json][:rkey] == "test-key"

        {:ok, %{status: 200, body: %{}}}
      end)

      assert :ok = Client.delete_record(session, "test-key", pds_url: @pds_url)
    end

    test "returns not_found for missing record", %{session: session} do
      Tessera.MockHTTPClient
      |> expect(:post, fn _url, _opts ->
        {:ok, %{status: 400, body: %{"error" => "RecordNotFound"}}}
      end)

      assert {:error, :not_found} =
               Client.delete_record(session, "missing-key", pds_url: @pds_url)
    end
  end

  describe "list_records/3" do
    setup do
      session = %{
        access_jwt: "test-token",
        refresh_jwt: "refresh-token",
        did: "did:plc:abc123",
        handle: "test.user"
      }

      {:ok, session: session}
    end

    test "lists records successfully", %{session: session} do
      Tessera.MockHTTPClient
      |> expect(:get, fn url, opts ->
        assert url == "#{@pds_url}/xrpc/com.atproto.repo.listRecords"
        assert opts[:params][:repo] == "did:plc:abc123"

        {:ok,
         %{
           status: 200,
           body: %{
             "records" => [
               %{"uri" => "at://did/collection/key1", "value" => %{"data" => "1"}},
               %{"uri" => "at://did/collection/key2", "value" => %{"data" => "2"}}
             ]
           }
         }}
      end)

      assert {:ok, result} = Client.list_records(session, "did:plc:abc123", pds_url: @pds_url)
      assert length(result["records"]) == 2
    end
  end
end
