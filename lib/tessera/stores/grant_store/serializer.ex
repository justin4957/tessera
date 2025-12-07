defmodule Tessera.Stores.GrantStore.Serializer do
  @moduledoc """
  Serialization and deserialization for Grant structs.

  Handles conversion between Grant structs and JSON-compatible maps
  for persistence in various storage backends.

  ## Serialization Format

  Grants are serialized with the following structure:

      %{
        "id" => "grant_abc123",
        "grantee_id" => "did:web:alice.example",
        "resource_id" => "pod://bob.example/data",
        "interval" => %{
          "start_time" => "2024-01-01T00:00:00Z",
          "end_time" => "2024-03-31T23:59:59Z"
        },
        "scope" => ["read", "write"],
        "purpose" => "insurance_claim",
        "context" => %{...},
        "frozen" => false,
        "revoked_at" => nil,
        "created_at" => "2024-01-01T00:00:00Z",
        "version" => 1
      }

  ## Version History

  - Version 1: Initial format
  """

  alias Tessera.Core.Grants.Grant
  alias Tessera.Core.Rights.TemporalInterval

  @current_version 1

  @doc """
  Serializes a Grant struct to a JSON-compatible map.

  ## Examples

      iex> grant = Grant.new(grantee_id: "alice", resource_id: "data", interval: interval, scope: [:read])
      iex> {:ok, map} = Serializer.serialize(grant)
      iex> map["grantee_id"]
      "alice"
  """
  @spec serialize(Grant.t()) :: {:ok, map()} | {:error, term()}
  def serialize(%Grant{} = grant) do
    serialized = %{
      "id" => grant.id,
      "grantee_id" => grant.grantee_id,
      "resource_id" => grant.resource_id,
      "interval" => serialize_interval(grant.interval),
      "scope" => Enum.map(grant.scope, &Atom.to_string/1),
      "purpose" => grant.purpose,
      "context" => grant.context,
      "frozen" => grant.frozen || false,
      "revoked_at" => serialize_datetime(grant.revoked_at),
      "created_at" => serialize_datetime(grant.created_at),
      "version" => @current_version
    }

    {:ok, serialized}
  end

  def serialize(_), do: {:error, :invalid_grant}

  @doc """
  Serializes a Grant struct to a JSON string.
  """
  @spec to_json(Grant.t()) :: {:ok, String.t()} | {:error, term()}
  def to_json(%Grant{} = grant) do
    with {:ok, map} <- serialize(grant) do
      Jason.encode(map)
    end
  end

  @doc """
  Deserializes a map to a Grant struct.

  Handles version migrations automatically.

  ## Examples

      iex> map = %{"id" => "abc", "grantee_id" => "alice", ...}
      iex> {:ok, grant} = Serializer.deserialize(map)
      iex> grant.grantee_id
      "alice"
  """
  @spec deserialize(map()) :: {:ok, Grant.t()} | {:error, term()}
  def deserialize(map) when is_map(map) do
    version = Map.get(map, "version", 1)

    with {:ok, migrated} <- migrate(map, version),
         {:ok, grant} <- build_grant(migrated) do
      {:ok, grant}
    end
  end

  def deserialize(_), do: {:error, :invalid_data}

  @doc """
  Deserializes a JSON string to a Grant struct.
  """
  @spec from_json(String.t()) :: {:ok, Grant.t()} | {:error, term()}
  def from_json(json) when is_binary(json) do
    with {:ok, map} <- Jason.decode(json) do
      deserialize(map)
    end
  end

  def from_json(_), do: {:error, :invalid_json}

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp serialize_interval(%TemporalInterval{} = interval) do
    %{
      "start_time" => serialize_datetime(interval.start_time),
      "end_time" => serialize_datetime(interval.end_time)
    }
  end

  defp serialize_interval(_), do: nil

  defp serialize_datetime(nil), do: nil
  defp serialize_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  defp deserialize_interval(%{"start_time" => start_str} = map) do
    with {:ok, start_time} <- parse_datetime(start_str) do
      end_time =
        case parse_datetime(map["end_time"]) do
          {:ok, dt} -> dt
          _ -> nil
        end

      {:ok, TemporalInterval.new(start_time, end_time)}
    end
  end

  defp deserialize_interval(_), do: {:error, :invalid_interval}

  defp parse_datetime(nil), do: {:ok, nil}

  defp parse_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _offset} -> {:ok, dt}
      {:error, _} -> {:error, :invalid_datetime}
    end
  end

  defp parse_datetime(_), do: {:error, :invalid_datetime}

  defp parse_scope(scope) when is_list(scope) do
    result =
      Enum.reduce_while(scope, [], fn
        s, acc when is_binary(s) ->
          atom = String.to_existing_atom(s)

          if atom in [:read, :write, :compute, :redact, :export] do
            {:cont, [atom | acc]}
          else
            {:halt, {:error, :invalid_scope}}
          end

        s, acc when is_atom(s) ->
          if s in [:read, :write, :compute, :redact, :export] do
            {:cont, [s | acc]}
          else
            {:halt, {:error, :invalid_scope}}
          end

        _, _ ->
          {:halt, {:error, :invalid_scope}}
      end)

    case result do
      {:error, _} = err -> err
      scopes -> {:ok, Enum.reverse(scopes)}
    end
  rescue
    ArgumentError -> {:error, :invalid_scope}
  end

  defp parse_scope(_), do: {:error, :invalid_scope}

  defp migrate(map, @current_version), do: {:ok, map}

  # Future migrations would go here:
  # defp migrate(map, 1) do
  #   # Migrate from v1 to v2
  #   migrated = Map.put(map, "new_field", default_value)
  #   migrate(migrated, 2)
  # end

  defp migrate(_map, version), do: {:error, {:unknown_version, version}}

  defp build_grant(map) do
    with {:ok, interval} <- deserialize_interval(map["interval"]),
         {:ok, scope} <- parse_scope(map["scope"]),
         {:ok, revoked_at} <- parse_datetime(map["revoked_at"]),
         {:ok, created_at} <- parse_datetime(map["created_at"]) do
      grant = %Grant{
        id: map["id"],
        grantee_id: map["grantee_id"],
        resource_id: map["resource_id"],
        interval: interval,
        scope: scope,
        purpose: map["purpose"],
        context: map["context"],
        frozen: map["frozen"] || false,
        revoked_at: revoked_at,
        created_at: created_at || DateTime.utc_now()
      }

      {:ok, grant}
    end
  end
end
