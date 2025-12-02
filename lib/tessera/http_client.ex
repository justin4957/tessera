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

  @impl true
  def put(url, opts \\ []) do
    Req.put(url, opts)
  end

  @impl true
  def delete(url, opts \\ []) do
    Req.delete(url, opts)
  end

  @impl true
  def head(url, opts \\ []) do
    Req.head(url, opts)
  end
end
