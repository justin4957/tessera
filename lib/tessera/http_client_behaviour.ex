defmodule Tessera.HTTPClientBehaviour do
  @moduledoc """
  Behaviour for HTTP clients, allowing for mocking in tests.
  """

  @type response :: %{status: integer(), body: term()}
  @type error :: {:error, term()}

  @callback get(url :: String.t(), opts :: keyword()) :: {:ok, response()} | error()
  @callback post(url :: String.t(), opts :: keyword()) :: {:ok, response()} | error()
end
