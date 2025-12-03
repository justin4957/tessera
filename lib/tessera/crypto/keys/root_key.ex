defmodule Tessera.Crypto.Keys.RootKey do
  @moduledoc """
  Root key in the hierarchical key derivation system.

  The root key is the master key from which all other keys are derived.
  It should be:
  - Generated from a cryptographically secure source
  - Stored securely (encrypted at rest)
  - Never exposed in logs or error messages

  ## Security Considerations

  - Root key compromise means all derived keys are compromised
  - Consider using HSM or secure enclave for storage
  - Implement key rotation policies
  - Use social recovery mechanisms for backup
  """

  @enforce_keys [:material, :created_at]
  defstruct [:material, :created_at, :key_id]

  @type t :: %__MODULE__{
          material: binary(),
          created_at: DateTime.t(),
          key_id: String.t() | nil
        }

  @doc """
  Creates a new root key from key material.
  """
  @spec new(binary()) :: t()
  def new(material) when is_binary(material) and byte_size(material) == 32 do
    %__MODULE__{
      material: material,
      created_at: DateTime.utc_now(),
      key_id: generate_key_id(material)
    }
  end

  @doc """
  Returns a truncated key ID for identification without exposing material.
  """
  @spec fingerprint(t()) :: String.t()
  def fingerprint(%__MODULE__{key_id: key_id}) do
    String.slice(key_id, 0, 16)
  end

  defp generate_key_id(material) do
    :crypto.hash(:sha256, material)
    |> Base.encode16(case: :lower)
    |> String.slice(0, 32)
  end

  defimpl Inspect do
    def inspect(%Tessera.Crypto.Keys.RootKey{key_id: key_id, created_at: created_at}, _opts) do
      fingerprint = String.slice(key_id || "", 0, 8)
      "#RootKey<#{fingerprint}... created_at: #{created_at}>"
    end
  end
end
