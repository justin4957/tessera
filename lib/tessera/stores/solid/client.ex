defmodule Tessera.Stores.Solid.Client do
  @moduledoc """
  Low-level HTTP client for Solid Pod operations.

  Implements the Solid Protocol for CRUD operations on Pod resources
  using the Linked Data Platform (LDP) specification.

  ## Solid Protocol Reference

  - [Solid Protocol](https://solidproject.org/TR/protocol)
  - [Solid-OIDC](https://solid.github.io/solid-oidc/)
  - [LDP Specification](https://www.w3.org/TR/ldp/)

  ## Authentication

  Supports Client Credentials flow for non-interactive authentication:
  1. Generate credentials via IDP endpoint
  2. Exchange credentials for access token with DPoP
  3. Use token for authenticated requests
  """

  @type session :: %{
          access_token: String.t(),
          token_type: String.t(),
          expires_at: DateTime.t() | nil,
          pod_url: String.t(),
          webid: String.t() | nil
        }

  @type error :: {:error, term()}

  @doc """
  Creates a session using client credentials authentication.

  This flow is suitable for server-to-server or script-based access
  without user interaction.

  ## Parameters

  - `pod_url` - Base URL of the Solid Pod
  - `credentials` - Map with `:id` and `:secret` from credential generation
  - `opts` - Options including `:token_endpoint`

  ## Returns

  - `{:ok, session}` on success
  - `{:error, reason}` on failure
  """
  @spec create_session(String.t(), map(), keyword()) :: {:ok, session()} | error()
  def create_session(pod_url, credentials, opts \\ []) do
    token_endpoint = Keyword.get(opts, :token_endpoint) || discover_token_endpoint(pod_url)

    case token_endpoint do
      {:ok, endpoint} ->
        request_access_token(pod_url, endpoint, credentials)

      {:error, _} = error ->
        error

      endpoint when is_binary(endpoint) ->
        request_access_token(pod_url, endpoint, credentials)
    end
  end

  @doc """
  Creates a session using email/password to first generate credentials,
  then authenticate. This is a convenience method for development.

  ## Parameters

  - `pod_url` - Base URL of the Solid Pod
  - `idp_url` - Identity Provider URL
  - `email` - Account email
  - `password` - Account password
  - `opts` - Additional options
  """
  @spec create_session_with_password(String.t(), String.t(), String.t(), String.t(), keyword()) ::
          {:ok, session()} | error()
  def create_session_with_password(pod_url, idp_url, email, password, opts \\ []) do
    token_name = Keyword.get(opts, :token_name, "tessera-#{System.system_time(:second)}")
    credentials_endpoint = "#{String.trim_trailing(idp_url, "/")}/idp/credentials/"

    body =
      Jason.encode!(%{
        email: email,
        password: password,
        name: token_name
      })

    case http_client().post(credentials_endpoint,
           body: body,
           headers: [{"content-type", "application/json"}]
         ) do
      {:ok, %{status: 200, body: %{"id" => id, "secret" => secret}}} ->
        create_session(pod_url, %{id: id, secret: secret}, opts)

      {:ok, %{status: status, body: body}} ->
        {:error, {:credential_generation_failed, status, body}}

      {:error, reason} ->
        {:error, {:network_error, reason}}
    end
  end

  @doc """
  Reads a resource from the Pod.

  ## Parameters

  - `session` - Authenticated session
  - `resource_path` - Path relative to Pod URL (or absolute URL)
  - `opts` - Options including `:accept` header for content negotiation
  """
  @spec get_resource(session(), String.t(), keyword()) :: {:ok, binary(), map()} | error()
  def get_resource(session, resource_path, opts \\ []) do
    url = resolve_url(session.pod_url, resource_path)
    accept = Keyword.get(opts, :accept, "application/json, application/ld+json, text/turtle, */*")

    headers = [
      {"accept", accept},
      {"authorization", "#{session.token_type} #{session.access_token}"}
    ]

    case http_client().get(url, headers: headers) do
      {:ok, %{status: 200, body: body, headers: resp_headers}} ->
        metadata = extract_metadata(resp_headers)
        {:ok, body, metadata}

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: 401}} ->
        {:error, :unauthorized}

      {:ok, %{status: 403}} ->
        {:error, :forbidden}

      {:ok, %{status: status, body: body}} ->
        {:error, {:get_failed, status, body}}

      {:error, reason} ->
        {:error, {:network_error, reason}}
    end
  end

  @doc """
  Creates or updates a resource in the Pod using PUT.

  PUT creates the resource if it doesn't exist, or replaces it if it does.

  ## Parameters

  - `session` - Authenticated session
  - `resource_path` - Path for the resource
  - `content` - Content to store
  - `opts` - Options including `:content_type`
  """
  @spec put_resource(session(), String.t(), binary(), keyword()) :: {:ok, map()} | error()
  def put_resource(session, resource_path, content, opts \\ []) do
    url = resolve_url(session.pod_url, resource_path)
    content_type = Keyword.get(opts, :content_type, "application/json")
    if_match = Keyword.get(opts, :if_match)
    if_none_match = Keyword.get(opts, :if_none_match)

    headers =
      [
        {"content-type", content_type},
        {"authorization", "#{session.token_type} #{session.access_token}"}
      ]
      |> maybe_add_header("if-match", if_match)
      |> maybe_add_header("if-none-match", if_none_match)

    case http_client().put(url, body: content, headers: headers) do
      {:ok, %{status: status, headers: resp_headers}} when status in [200, 201, 204] ->
        {:ok, extract_metadata(resp_headers)}

      {:ok, %{status: 401}} ->
        {:error, :unauthorized}

      {:ok, %{status: 403}} ->
        {:error, :forbidden}

      {:ok, %{status: 412}} ->
        {:error, :precondition_failed}

      {:ok, %{status: status, body: body}} ->
        {:error, {:put_failed, status, body}}

      {:error, reason} ->
        {:error, {:network_error, reason}}
    end
  end

  @doc """
  Creates a new resource using POST (server assigns URI).

  ## Parameters

  - `session` - Authenticated session
  - `container_path` - Path to the container
  - `content` - Content to store
  - `opts` - Options including `:content_type`, `:slug` (suggested name)
  """
  @spec post_resource(session(), String.t(), binary(), keyword()) ::
          {:ok, String.t(), map()} | error()
  def post_resource(session, container_path, content, opts \\ []) do
    url = resolve_url(session.pod_url, container_path)
    content_type = Keyword.get(opts, :content_type, "application/json")
    slug = Keyword.get(opts, :slug)

    headers =
      [
        {"content-type", content_type},
        {"authorization", "#{session.token_type} #{session.access_token}"}
      ]
      |> maybe_add_header("slug", slug)

    case http_client().post(url, body: content, headers: headers) do
      {:ok, %{status: 201, headers: resp_headers}} ->
        location = get_header(resp_headers, "location")
        {:ok, location, extract_metadata(resp_headers)}

      {:ok, %{status: 401}} ->
        {:error, :unauthorized}

      {:ok, %{status: 403}} ->
        {:error, :forbidden}

      {:ok, %{status: status, body: body}} ->
        {:error, {:post_failed, status, body}}

      {:error, reason} ->
        {:error, {:network_error, reason}}
    end
  end

  @doc """
  Deletes a resource from the Pod.

  ## Parameters

  - `session` - Authenticated session
  - `resource_path` - Path to the resource
  """
  @spec delete_resource(session(), String.t()) :: :ok | error()
  def delete_resource(session, resource_path) do
    url = resolve_url(session.pod_url, resource_path)

    headers = [
      {"authorization", "#{session.token_type} #{session.access_token}"}
    ]

    case http_client().delete(url, headers: headers) do
      {:ok, %{status: status}} when status in [200, 204] ->
        :ok

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: 401}} ->
        {:error, :unauthorized}

      {:ok, %{status: 403}} ->
        {:error, :forbidden}

      {:ok, %{status: status, body: body}} ->
        {:error, {:delete_failed, status, body}}

      {:error, reason} ->
        {:error, {:network_error, reason}}
    end
  end

  @doc """
  Checks if a resource exists using HEAD request.

  ## Parameters

  - `session` - Authenticated session
  - `resource_path` - Path to the resource
  """
  @spec head_resource(session(), String.t()) :: {:ok, map()} | error()
  def head_resource(session, resource_path) do
    url = resolve_url(session.pod_url, resource_path)

    headers = [
      {"authorization", "#{session.token_type} #{session.access_token}"}
    ]

    case http_client().head(url, headers: headers) do
      {:ok, %{status: 200, headers: resp_headers}} ->
        {:ok, extract_metadata(resp_headers)}

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: 401}} ->
        {:error, :unauthorized}

      {:ok, %{status: status}} ->
        {:error, {:head_failed, status}}

      {:error, reason} ->
        {:error, {:network_error, reason}}
    end
  end

  @doc """
  Lists contents of a container.

  ## Parameters

  - `session` - Authenticated session
  - `container_path` - Path to the container
  """
  @spec list_container(session(), String.t()) :: {:ok, [String.t()]} | error()
  def list_container(session, container_path) do
    # Ensure container path ends with /
    container_path = String.trim_trailing(container_path, "/") <> "/"

    case get_resource(session, container_path, accept: "application/ld+json, text/turtle") do
      {:ok, body, _metadata} ->
        resources = parse_container_contents(body)
        {:ok, resources}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Creates a container (directory) in the Pod.

  ## Parameters

  - `session` - Authenticated session
  - `container_path` - Path for the new container
  """
  @spec create_container(session(), String.t()) :: {:ok, map()} | error()
  def create_container(session, container_path) do
    # Containers are created by PUT with Link header indicating BasicContainer
    url = resolve_url(session.pod_url, String.trim_trailing(container_path, "/") <> "/")

    headers = [
      {"content-type", "text/turtle"},
      {"link", "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\""},
      {"authorization", "#{session.token_type} #{session.access_token}"}
    ]

    # Empty container body
    body = ""

    case http_client().put(url, body: body, headers: headers) do
      {:ok, %{status: status, headers: resp_headers}} when status in [200, 201, 204] ->
        {:ok, extract_metadata(resp_headers)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:create_container_failed, status, body}}

      {:error, reason} ->
        {:error, {:network_error, reason}}
    end
  end

  # Private helpers

  defp discover_token_endpoint(pod_url) do
    # Try to discover OIDC configuration
    base_url = extract_base_url(pod_url)
    well_known_url = "#{base_url}/.well-known/openid-configuration"

    case http_client().get(well_known_url, []) do
      {:ok, %{status: 200, body: body}} when is_map(body) ->
        {:ok, body["token_endpoint"]}

      {:ok, %{status: 200, body: body}} when is_binary(body) ->
        case Jason.decode(body) do
          {:ok, config} -> {:ok, config["token_endpoint"]}
          _ -> {:error, :invalid_oidc_config}
        end

      _ ->
        # Fallback to common CSS endpoint
        {:ok, "#{base_url}/.oidc/token"}
    end
  end

  defp request_access_token(pod_url, token_endpoint, %{id: id, secret: secret}) do
    auth = Base.encode64("#{id}:#{secret}")

    headers = [
      {"authorization", "Basic #{auth}"},
      {"content-type", "application/x-www-form-urlencoded"}
    ]

    body = "grant_type=client_credentials&scope=webid"

    case http_client().post(token_endpoint, body: body, headers: headers) do
      {:ok, %{status: 200, body: body}} ->
        token_data = if is_binary(body), do: Jason.decode!(body), else: body

        expires_at =
          if expires_in = token_data["expires_in"] do
            DateTime.add(DateTime.utc_now(), expires_in, :second)
          end

        {:ok,
         %{
           access_token: token_data["access_token"],
           token_type: token_data["token_type"] || "Bearer",
           expires_at: expires_at,
           pod_url: pod_url,
           webid: token_data["webid"]
         }}

      {:ok, %{status: status, body: body}} ->
        {:error, {:token_request_failed, status, body}}

      {:error, reason} ->
        {:error, {:network_error, reason}}
    end
  end

  defp resolve_url(pod_url, path) do
    if String.starts_with?(path, "http://") || String.starts_with?(path, "https://") do
      path
    else
      base = String.trim_trailing(pod_url, "/")
      path = String.trim_leading(path, "/")
      "#{base}/#{path}"
    end
  end

  defp extract_base_url(url) do
    uri = URI.parse(url)

    "#{uri.scheme}://#{uri.host}#{if uri.port && uri.port not in [80, 443], do: ":#{uri.port}", else: ""}"
  end

  defp extract_metadata(headers) do
    headers_map =
      headers
      |> Enum.map(fn {k, v} -> {String.downcase(to_string(k)), v} end)
      |> Map.new()

    %{
      etag: headers_map["etag"],
      content_type: headers_map["content-type"],
      last_modified: headers_map["last-modified"],
      location: headers_map["location"]
    }
  end

  defp get_header(headers, name) do
    name = String.downcase(name)

    Enum.find_value(headers, fn {k, v} ->
      if String.downcase(to_string(k)) == name, do: v
    end)
  end

  defp maybe_add_header(headers, _name, nil), do: headers
  defp maybe_add_header(headers, name, value), do: [{name, value} | headers]

  defp parse_container_contents(body) when is_binary(body) do
    # Simple parsing for JSON-LD or Turtle container listings
    # Look for ldp:contains references
    cond do
      String.contains?(body, "ldp:contains") || String.contains?(body, "contains") ->
        # Try to extract URLs from various formats
        extract_contained_resources(body)

      true ->
        []
    end
  end

  defp parse_container_contents(body) when is_map(body) do
    # JSON-LD format
    contains =
      body["contains"] || body["ldp:contains"] ||
        get_in(body, ["@graph", Access.all(), "ldp:contains"]) || []

    contains
    |> List.wrap()
    |> Enum.flat_map(fn
      %{"@id" => id} -> [id]
      id when is_binary(id) -> [id]
      _ -> []
    end)
  end

  defp parse_container_contents(_), do: []

  defp extract_contained_resources(body) do
    # Extract URLs that look like contained resources
    # This handles both Turtle and JSON-LD formats
    url_pattern = ~r{<([^>]+)>|"(@id|url)":\s*"([^"]+)"}

    Regex.scan(url_pattern, body)
    |> Enum.flat_map(fn
      [_, url, "", ""] -> [url]
      [_, "", _, url] -> [url]
      [_, url] -> [url]
      _ -> []
    end)
    |> Enum.filter(&String.starts_with?(&1, "http"))
    |> Enum.uniq()
  end

  defp http_client do
    Application.get_env(:tessera, :http_client, Tessera.HTTPClient)
  end
end
