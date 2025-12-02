defmodule Tessera do
  @moduledoc """
  Tessera - Temporal Data Sovereignty with Pluggable Storage Backends

  Tessera enables control over *when* data is accessible, not merely *to whom*.
  It implements a formal temporal rights algebra for fine-grained, time-bounded
  access control across multiple storage backends.

  ## Core Concepts

  - **Temporal Intervals**: Time-bounded windows for data access
  - **Grants**: Bind users, resources, time intervals, and permissions
  - **Stores**: Pluggable backends (Solid Pods, ATProto, Memory, etc.)

  ## Quick Start

      # Start the memory store
      {:ok, _} = Tessera.Stores.Memory.Adapter.start_link()

      # Create a temporal grant
      alias Tessera.Core.{Grants.Grant, Rights.TemporalInterval}

      grant = Grant.new(
        grantee_id: "did:web:alice.example",
        resource_id: "data/records/001",
        interval: TemporalInterval.for_duration(30, :day),
        scope: [:read]
      )

      # Check if grant is active
      Grant.active?(grant)  # => true

  ## Architecture

  Tessera is organized into layers:

  - `Tessera.Core.Rights` - Temporal rights algebra
  - `Tessera.Core.Grants` - Grant lifecycle management
  - `Tessera.Stores` - Pluggable storage backends
  - `Tessera.Temporal` - Time-lock primitives (planned)
  - `Tessera.Crypto` - Cryptographic foundations (planned)
  """

  @doc """
  Returns the current version of Tessera.
  """
  def version do
    "0.1.0"
  end
end
