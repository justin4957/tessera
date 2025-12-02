defmodule TesseraTest do
  use ExUnit.Case
  doctest Tessera

  test "returns version" do
    assert Tessera.version() == "0.1.0"
  end
end
