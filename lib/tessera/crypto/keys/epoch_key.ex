defmodule Tessera.Crypto.Keys.EpochKey do
  @moduledoc """
  Epoch key in the hierarchical key derivation system.

  Epoch keys provide forward secrecy by rotating keys at defined intervals.
  When an epoch expires, its key can be securely deleted to prevent
  decryption of historical data (even if root key is later compromised).

  ## Key Hierarchy

  ```
  RootKey
      └── ConversationKey
              └── EpochKey (this level)
                      └── MessageKey
  ```

  ## Forward Secrecy

  Epoch keys enable a "forget" operation:
  1. Data is encrypted with message keys derived from epoch keys
  2. When access should end, delete the epoch key
  3. Data becomes cryptographically inaccessible
  4. Root key compromise doesn't help - epoch key is gone

  ## Epoch Numbering

  Epochs are numbered sequentially (0, 1, 2, ...).
  The epoch number can represent:
  - Time periods (epoch 0 = first hour, epoch 1 = second hour)
  - Rotation count (manual or automatic rotation)
  - Version numbers for key updates
  """

  alias Tessera.Crypto.Keys.ConversationKey

  @enforce_keys [:material, :epoch_number, :created_at, :parent]
  defstruct [:material, :epoch_number, :created_at, :key_id, :parent]

  @type t :: %__MODULE__{
          material: binary(),
          epoch_number: non_neg_integer(),
          created_at: DateTime.t(),
          key_id: String.t() | nil,
          parent: ConversationKey.t()
        }

  @doc """
  Creates a new epoch key from derived material.
  """
  @spec new(binary(), non_neg_integer(), ConversationKey.t()) :: t()
  def new(material, epoch_number, %ConversationKey{} = parent)
      when is_binary(material) and byte_size(material) == 32 and
             is_integer(epoch_number) and epoch_number >= 0 do
    %__MODULE__{
      material: material,
      epoch_number: epoch_number,
      created_at: DateTime.utc_now(),
      key_id: generate_key_id(material),
      parent: parent
    }
  end

  @doc """
  Returns a truncated key ID for identification without exposing material.
  """
  @spec fingerprint(t()) :: String.t()
  def fingerprint(%__MODULE__{key_id: key_id}) do
    String.slice(key_id, 0, 16)
  end

  @doc """
  Returns the conversation ID this epoch key belongs to.
  """
  @spec conversation_id(t()) :: String.t()
  def conversation_id(%__MODULE__{parent: parent}) do
    parent.conversation_id
  end

  defp generate_key_id(material) do
    :crypto.hash(:sha256, material)
    |> Base.encode16(case: :lower)
    |> String.slice(0, 32)
  end

  defimpl Inspect do
    def inspect(
          %Tessera.Crypto.Keys.EpochKey{
            key_id: key_id,
            epoch_number: epoch,
            parent: parent,
            created_at: created_at
          },
          _opts
        ) do
      fingerprint = String.slice(key_id || "", 0, 8)
      conv_id = parent.conversation_id
      "#EpochKey<#{fingerprint}... conv: #{conv_id}, epoch: #{epoch}, created_at: #{created_at}>"
    end
  end
end
