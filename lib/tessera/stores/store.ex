defmodule Tessera.Store do
  @moduledoc """
  Behaviour defining the interface for pluggable storage backends.

  Tessera supports multiple data store implementations:
  - Solid Pods (W3C standard personal data stores)
  - ATProto PDS (Bluesky Personal Data Servers)
  - Memory (for testing and development)
  - Custom implementations

  All stores must implement this behaviour to be compatible with
  the Tessera temporal rights system.
  """

  @type resource_id :: String.t()
  @type user_id :: String.t()
  @type data :: term()
  @type metadata :: map()
  @type error :: {:error, term()}

  @doc """
  Stores data with the given resource identifier.
  """
  @callback put(resource_id(), data(), metadata()) :: :ok | error()

  @doc """
  Retrieves data by resource identifier.
  """
  @callback get(resource_id()) :: {:ok, data(), metadata()} | {:error, :not_found} | error()

  @doc """
  Deletes data by resource identifier.
  """
  @callback delete(resource_id()) :: :ok | {:error, :not_found} | error()

  @doc """
  Lists all resource identifiers, optionally filtered by prefix.
  """
  @callback list(prefix :: String.t() | nil) :: {:ok, [resource_id()]} | error()

  @doc """
  Checks if a resource exists.
  """
  @callback exists?(resource_id()) :: boolean()

  @doc """
  Returns metadata about the store (type, capabilities, connection info).
  """
  @callback info() :: map()

  @doc """
  Optional: Performs any necessary connection/initialization.
  """
  @callback connect(opts :: keyword()) :: :ok | error()

  @doc """
  Optional: Gracefully disconnects from the store.
  """
  @callback disconnect() :: :ok

  @optional_callbacks [connect: 1, disconnect: 0]
end
