defmodule Tessera.Stores.GrantStore do
  @moduledoc """
  Behaviour defining the interface for grant persistence.

  Grant stores handle the storage, retrieval, and querying of temporal access
  grants. This enables grants to survive process restarts and be queryable
  across time.

  ## Implementations

  - `Tessera.Stores.GrantStore.Memory` - In-memory (ETS) for testing
  - `Tessera.Stores.GrantStore.Solid` - Solid Pod persistence
  - `Tessera.Stores.GrantStore.ATProto` - ATProto PDS persistence

  ## Usage

      # Store a grant
      {:ok, grant} = GrantStore.store_grant(adapter, grant)

      # Retrieve by ID
      {:ok, grant} = GrantStore.get_grant(adapter, grant_id)

      # Query grants
      {:ok, grants} = GrantStore.list_grants_for_resource(adapter, resource_id)
      {:ok, grants} = GrantStore.list_grants_for_grantee(adapter, grantee_id)

      # Revoke a grant
      {:ok, revoked} = GrantStore.revoke_grant(adapter, grant_id)

  ## Indexing

  Implementations should maintain indexes for efficient querying by:
  - Grant ID (primary key)
  - Resource ID
  - Grantee ID
  - Time-based queries (active grants at a point in time)
  """

  alias Tessera.Core.Grants.Grant

  @type grant_id :: String.t()
  @type resource_id :: String.t()
  @type grantee_id :: String.t()
  @type error :: {:error, term()}

  # ============================================================================
  # Core CRUD Operations
  # ============================================================================

  @doc """
  Stores a grant in the persistence layer.

  If the grant already exists (by ID), it will be updated.
  Frozen grants cannot be updated after initial storage.

  ## Returns

  - `{:ok, grant}` - Successfully stored
  - `{:error, :frozen}` - Cannot update a frozen grant
  - `{:error, reason}` - Storage failed
  """
  @callback store_grant(Grant.t()) :: {:ok, Grant.t()} | error()

  @doc """
  Retrieves a grant by its ID.

  ## Returns

  - `{:ok, grant}` - Grant found
  - `{:error, :not_found}` - Grant does not exist
  """
  @callback get_grant(grant_id()) :: {:ok, Grant.t()} | {:error, :not_found} | error()

  @doc """
  Deletes a grant from storage.

  Note: For audit purposes, consider using `revoke_grant/1` instead of
  deleting grants entirely.

  ## Returns

  - `:ok` - Successfully deleted
  - `{:error, :not_found}` - Grant does not exist
  - `{:error, :frozen}` - Cannot delete a frozen grant
  """
  @callback delete_grant(grant_id()) :: :ok | {:error, :not_found | :frozen} | error()

  # ============================================================================
  # Query Operations
  # ============================================================================

  @doc """
  Lists all grants for a specific resource.

  ## Options

  - `:active_only` - Only return currently active grants (default: false)
  - `:include_revoked` - Include revoked grants (default: true)
  - `:at` - Query grants active at a specific DateTime

  ## Returns

  - `{:ok, [grant]}` - List of matching grants (may be empty)
  """
  @callback list_grants_for_resource(resource_id(), opts :: keyword()) ::
              {:ok, [Grant.t()]} | error()

  @doc """
  Lists all grants for a specific grantee.

  ## Options

  - `:active_only` - Only return currently active grants (default: false)
  - `:include_revoked` - Include revoked grants (default: true)
  - `:at` - Query grants active at a specific DateTime

  ## Returns

  - `{:ok, [grant]}` - List of matching grants (may be empty)
  """
  @callback list_grants_for_grantee(grantee_id(), opts :: keyword()) ::
              {:ok, [Grant.t()]} | error()

  @doc """
  Lists all grants, optionally filtered.

  ## Options

  - `:active_only` - Only return currently active grants (default: false)
  - `:include_revoked` - Include revoked grants (default: true)
  - `:limit` - Maximum number of grants to return
  - `:offset` - Number of grants to skip (for pagination)

  ## Returns

  - `{:ok, [grant]}` - List of matching grants
  """
  @callback list_grants(opts :: keyword()) :: {:ok, [Grant.t()]} | error()

  # ============================================================================
  # Grant Lifecycle Operations
  # ============================================================================

  @doc """
  Revokes a grant by ID.

  This updates the grant's `revoked_at` timestamp and truncates the
  temporal interval. Historical access remains provable.

  ## Returns

  - `{:ok, grant}` - Grant successfully revoked
  - `{:error, :not_found}` - Grant does not exist
  - `{:error, :already_revoked}` - Grant was already revoked
  - `{:error, :frozen}` - Cannot revoke a frozen grant
  """
  @callback revoke_grant(grant_id()) :: {:ok, Grant.t()} | error()

  @doc """
  Freezes a grant, making it immutable.

  Frozen grants cannot be modified or revoked. This creates an
  immutable audit record.

  ## Returns

  - `{:ok, grant}` - Grant successfully frozen
  - `{:error, :not_found}` - Grant does not exist
  - `{:error, :already_frozen}` - Grant was already frozen
  """
  @callback freeze_grant(grant_id()) :: {:ok, Grant.t()} | error()

  # ============================================================================
  # Adapter Information
  # ============================================================================

  @doc """
  Returns information about the grant store adapter.

  ## Returns

  Map containing:
  - `:type` - Adapter type (:memory, :solid, :atproto)
  - `:grant_count` - Number of stored grants
  - `:persistent` - Whether grants survive restarts
  - `:capabilities` - List of supported features
  """
  @callback info() :: map()

  @optional_callbacks []

  # ============================================================================
  # Public API (Delegates to Adapter)
  # ============================================================================

  @doc """
  Stores a grant using the specified adapter.
  """
  @spec store_grant(module(), Grant.t()) :: {:ok, Grant.t()} | error()
  def store_grant(adapter, grant) do
    adapter.store_grant(grant)
  end

  @doc """
  Retrieves a grant by ID using the specified adapter.
  """
  @spec get_grant(module(), grant_id()) :: {:ok, Grant.t()} | error()
  def get_grant(adapter, grant_id) do
    adapter.get_grant(grant_id)
  end

  @doc """
  Deletes a grant using the specified adapter.
  """
  @spec delete_grant(module(), grant_id()) :: :ok | error()
  def delete_grant(adapter, grant_id) do
    adapter.delete_grant(grant_id)
  end

  @doc """
  Lists grants for a resource using the specified adapter.
  """
  @spec list_grants_for_resource(module(), resource_id(), keyword()) ::
          {:ok, [Grant.t()]} | error()
  def list_grants_for_resource(adapter, resource_id, opts \\ []) do
    adapter.list_grants_for_resource(resource_id, opts)
  end

  @doc """
  Lists grants for a grantee using the specified adapter.
  """
  @spec list_grants_for_grantee(module(), grantee_id(), keyword()) :: {:ok, [Grant.t()]} | error()
  def list_grants_for_grantee(adapter, grantee_id, opts \\ []) do
    adapter.list_grants_for_grantee(grantee_id, opts)
  end

  @doc """
  Lists all grants using the specified adapter.
  """
  @spec list_grants(module(), keyword()) :: {:ok, [Grant.t()]} | error()
  def list_grants(adapter, opts \\ []) do
    adapter.list_grants(opts)
  end

  @doc """
  Revokes a grant using the specified adapter.
  """
  @spec revoke_grant(module(), grant_id()) :: {:ok, Grant.t()} | error()
  def revoke_grant(adapter, grant_id) do
    adapter.revoke_grant(grant_id)
  end

  @doc """
  Freezes a grant using the specified adapter.
  """
  @spec freeze_grant(module(), grant_id()) :: {:ok, Grant.t()} | error()
  def freeze_grant(adapter, grant_id) do
    adapter.freeze_grant(grant_id)
  end

  @doc """
  Returns adapter information.
  """
  @spec info(module()) :: map()
  def info(adapter) do
    adapter.info()
  end
end
