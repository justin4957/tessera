defmodule Tessera.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Start the default memory store
      {Tessera.Stores.Memory.Adapter, name: Tessera.Stores.Memory.Adapter}
    ]

    opts = [strategy: :one_for_one, name: Tessera.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
