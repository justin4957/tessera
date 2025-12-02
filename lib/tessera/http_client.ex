defmodule Tessera.HTTPClient do
  @moduledoc """
  Default HTTP client implementation using Req.
  """

  @behaviour Tessera.HTTPClientBehaviour

  @impl true
  def get(url, opts \\ []) do
    Req.get(url, opts)
  end

  @impl true
  def post(url, opts \\ []) do
    Req.post(url, opts)
  end
end
