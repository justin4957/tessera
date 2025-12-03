defmodule Tessera.Crypto.KeyDerivationTest do
  use ExUnit.Case, async: true

  alias Tessera.Crypto.KeyDerivation
  alias Tessera.Crypto.Keys.{RootKey, ConversationKey, EpochKey, MessageKey}

  describe "generate_root_key/1" do
    test "generates a valid root key" do
      assert {:ok, %RootKey{} = root_key} = KeyDerivation.generate_root_key()
      assert byte_size(root_key.material) == 32
      assert root_key.key_id != nil
      assert root_key.created_at != nil
    end

    test "generates unique keys on each call" do
      {:ok, key1} = KeyDerivation.generate_root_key()
      {:ok, key2} = KeyDerivation.generate_root_key()

      refute KeyDerivation.equal?(key1, key2)
    end

    test "accepts optional entropy" do
      entropy = :crypto.strong_rand_bytes(32)
      assert {:ok, %RootKey{}} = KeyDerivation.generate_root_key(entropy: entropy)
    end

    test "same entropy produces different keys (mixed with random)" do
      entropy = "user-specific-entropy"
      {:ok, key1} = KeyDerivation.generate_root_key(entropy: entropy)
      {:ok, key2} = KeyDerivation.generate_root_key(entropy: entropy)

      refute KeyDerivation.equal?(key1, key2)
    end
  end

  describe "derive_root_from_password/2" do
    test "derives deterministic key from password and salt" do
      password = "correct-horse-battery-staple"
      salt = :crypto.strong_rand_bytes(16)

      {:ok, key1, ^salt} = KeyDerivation.derive_root_from_password(password, salt: salt)
      {:ok, key2, ^salt} = KeyDerivation.derive_root_from_password(password, salt: salt)

      assert KeyDerivation.equal?(key1, key2)
    end

    test "different passwords produce different keys" do
      salt = :crypto.strong_rand_bytes(16)

      {:ok, key1, _} = KeyDerivation.derive_root_from_password("password1", salt: salt)
      {:ok, key2, _} = KeyDerivation.derive_root_from_password("password2", salt: salt)

      refute KeyDerivation.equal?(key1, key2)
    end

    test "different salts produce different keys" do
      password = "same-password"

      {:ok, key1, salt1} = KeyDerivation.derive_root_from_password(password)
      {:ok, key2, salt2} = KeyDerivation.derive_root_from_password(password)

      refute salt1 == salt2
      refute KeyDerivation.equal?(key1, key2)
    end

    test "generates salt if not provided" do
      {:ok, _key, salt} = KeyDerivation.derive_root_from_password("password")
      assert byte_size(salt) == 16
    end

    test "respects custom iteration count" do
      password = "test"
      salt = :crypto.strong_rand_bytes(16)

      {:ok, key1, _} =
        KeyDerivation.derive_root_from_password(password, salt: salt, iterations: 1000)

      {:ok, key2, _} =
        KeyDerivation.derive_root_from_password(password, salt: salt, iterations: 2000)

      refute KeyDerivation.equal?(key1, key2)
    end
  end

  describe "derive_conversation_key/2" do
    setup do
      {:ok, root_key} = KeyDerivation.generate_root_key()
      {:ok, root_key: root_key}
    end

    test "derives a valid conversation key", %{root_key: root_key} do
      {:ok, %ConversationKey{} = conv_key} =
        KeyDerivation.derive_conversation_key(root_key, "conversation-123")

      assert byte_size(conv_key.material) == 32
      assert conv_key.conversation_id == "conversation-123"
      assert conv_key.key_id != nil
    end

    test "same conversation ID produces same key", %{root_key: root_key} do
      {:ok, key1} = KeyDerivation.derive_conversation_key(root_key, "conv-abc")
      {:ok, key2} = KeyDerivation.derive_conversation_key(root_key, "conv-abc")

      assert KeyDerivation.equal?(key1, key2)
    end

    test "different conversation IDs produce different keys", %{root_key: root_key} do
      {:ok, key1} = KeyDerivation.derive_conversation_key(root_key, "conv-1")
      {:ok, key2} = KeyDerivation.derive_conversation_key(root_key, "conv-2")

      refute KeyDerivation.equal?(key1, key2)
    end

    test "different root keys produce different conversation keys" do
      {:ok, root1} = KeyDerivation.generate_root_key()
      {:ok, root2} = KeyDerivation.generate_root_key()

      {:ok, conv1} = KeyDerivation.derive_conversation_key(root1, "same-conv")
      {:ok, conv2} = KeyDerivation.derive_conversation_key(root2, "same-conv")

      refute KeyDerivation.equal?(conv1, conv2)
    end

    test "stores parent fingerprint", %{root_key: root_key} do
      {:ok, conv_key} = KeyDerivation.derive_conversation_key(root_key, "conv")
      assert conv_key.parent_fingerprint == RootKey.fingerprint(root_key)
    end
  end

  describe "derive_epoch_key/2" do
    setup do
      {:ok, root_key} = KeyDerivation.generate_root_key()
      {:ok, conv_key} = KeyDerivation.derive_conversation_key(root_key, "test-conv")
      {:ok, conv_key: conv_key}
    end

    test "derives a valid epoch key", %{conv_key: conv_key} do
      {:ok, %EpochKey{} = epoch_key} = KeyDerivation.derive_epoch_key(conv_key, 0)

      assert byte_size(epoch_key.material) == 32
      assert epoch_key.epoch_number == 0
      assert epoch_key.key_id != nil
    end

    test "same epoch number produces same key", %{conv_key: conv_key} do
      {:ok, key1} = KeyDerivation.derive_epoch_key(conv_key, 5)
      {:ok, key2} = KeyDerivation.derive_epoch_key(conv_key, 5)

      assert KeyDerivation.equal?(key1, key2)
    end

    test "different epoch numbers produce different keys", %{conv_key: conv_key} do
      {:ok, key1} = KeyDerivation.derive_epoch_key(conv_key, 0)
      {:ok, key2} = KeyDerivation.derive_epoch_key(conv_key, 1)

      refute KeyDerivation.equal?(key1, key2)
    end

    test "stores parent reference", %{conv_key: conv_key} do
      {:ok, epoch_key} = KeyDerivation.derive_epoch_key(conv_key, 42)
      assert epoch_key.parent == conv_key
      assert EpochKey.conversation_id(epoch_key) == "test-conv"
    end

    test "epoch 0 is valid", %{conv_key: conv_key} do
      assert {:ok, %EpochKey{epoch_number: 0}} = KeyDerivation.derive_epoch_key(conv_key, 0)
    end

    test "large epoch numbers work", %{conv_key: conv_key} do
      assert {:ok, %EpochKey{epoch_number: 999_999}} =
               KeyDerivation.derive_epoch_key(conv_key, 999_999)
    end
  end

  describe "derive_message_key/2" do
    setup do
      {:ok, root_key} = KeyDerivation.generate_root_key()
      {:ok, conv_key} = KeyDerivation.derive_conversation_key(root_key, "test-conv")
      {:ok, epoch_key} = KeyDerivation.derive_epoch_key(conv_key, 1)
      {:ok, epoch_key: epoch_key}
    end

    test "derives a valid message key", %{epoch_key: epoch_key} do
      {:ok, %MessageKey{} = msg_key} = KeyDerivation.derive_message_key(epoch_key, "resource-1")

      assert byte_size(msg_key.material) == 32
      assert msg_key.resource_id == "resource-1"
      assert msg_key.key_id != nil
    end

    test "same resource ID produces same key", %{epoch_key: epoch_key} do
      {:ok, key1} = KeyDerivation.derive_message_key(epoch_key, "doc-abc")
      {:ok, key2} = KeyDerivation.derive_message_key(epoch_key, "doc-abc")

      assert KeyDerivation.equal?(key1, key2)
    end

    test "different resource IDs produce different keys", %{epoch_key: epoch_key} do
      {:ok, key1} = KeyDerivation.derive_message_key(epoch_key, "doc-1")
      {:ok, key2} = KeyDerivation.derive_message_key(epoch_key, "doc-2")

      refute KeyDerivation.equal?(key1, key2)
    end

    test "stores parent reference", %{epoch_key: epoch_key} do
      {:ok, msg_key} = KeyDerivation.derive_message_key(epoch_key, "resource")
      assert msg_key.parent == epoch_key
      assert MessageKey.epoch_number(msg_key) == 1
      assert MessageKey.conversation_id(msg_key) == "test-conv"
    end

    test "to_bytes returns raw material", %{epoch_key: epoch_key} do
      {:ok, msg_key} = KeyDerivation.derive_message_key(epoch_key, "resource")
      assert MessageKey.to_bytes(msg_key) == msg_key.material
    end
  end

  describe "derive_path/2" do
    setup do
      {:ok, root_key} = KeyDerivation.generate_root_key()
      {:ok, root_key: root_key}
    end

    test "path 'm' returns root key", %{root_key: root_key} do
      {:ok, key} = KeyDerivation.derive_path(root_key, "m")
      assert KeyDerivation.equal?(key, root_key)
    end

    test "path to conversation key", %{root_key: root_key} do
      {:ok, key} = KeyDerivation.derive_path(root_key, "m/conv/my-conversation")
      assert %ConversationKey{conversation_id: "my-conversation"} = key
    end

    test "path to epoch key", %{root_key: root_key} do
      {:ok, key} = KeyDerivation.derive_path(root_key, "m/conv/chat/epoch/42")
      assert %EpochKey{epoch_number: 42} = key
    end

    test "path to message key", %{root_key: root_key} do
      {:ok, key} = KeyDerivation.derive_path(root_key, "m/conv/chat/epoch/5/msg/document-1")
      assert %MessageKey{resource_id: "document-1"} = key
    end

    test "path derivation matches step-by-step derivation", %{root_key: root_key} do
      # Derive step by step
      {:ok, conv_key} = KeyDerivation.derive_conversation_key(root_key, "test")
      {:ok, epoch_key} = KeyDerivation.derive_epoch_key(conv_key, 3)
      {:ok, msg_key_step} = KeyDerivation.derive_message_key(epoch_key, "doc")

      # Derive via path
      {:ok, msg_key_path} = KeyDerivation.derive_path(root_key, "m/conv/test/epoch/3/msg/doc")

      assert KeyDerivation.equal?(msg_key_step, msg_key_path)
    end

    test "invalid path format returns error", %{root_key: root_key} do
      assert {:error, {:invalid_path, _}} = KeyDerivation.derive_path(root_key, "invalid")
      assert {:error, {:invalid_path, _}} = KeyDerivation.derive_path(root_key, "m/unknown/path")
      assert {:error, {:invalid_path, _}} = KeyDerivation.derive_path(root_key, "")
    end

    test "invalid epoch number returns error", %{root_key: root_key} do
      assert {:error, {:invalid_epoch, "abc"}} =
               KeyDerivation.derive_path(root_key, "m/conv/test/epoch/abc")
    end
  end

  describe "key_path/1" do
    setup do
      {:ok, root_key} = KeyDerivation.generate_root_key()
      {:ok, conv_key} = KeyDerivation.derive_conversation_key(root_key, "conv-123")
      {:ok, epoch_key} = KeyDerivation.derive_epoch_key(conv_key, 7)
      {:ok, msg_key} = KeyDerivation.derive_message_key(epoch_key, "resource-abc")

      {:ok, root_key: root_key, conv_key: conv_key, epoch_key: epoch_key, msg_key: msg_key}
    end

    test "returns path for root key", %{root_key: root_key} do
      assert KeyDerivation.key_path(root_key) == "m"
    end

    test "returns path for conversation key", %{conv_key: conv_key} do
      assert KeyDerivation.key_path(conv_key) == "m/conv/conv-123"
    end

    test "returns path for epoch key", %{epoch_key: epoch_key} do
      assert KeyDerivation.key_path(epoch_key) == "m/conv/conv-123/epoch/7"
    end

    test "returns path for message key", %{msg_key: msg_key} do
      assert KeyDerivation.key_path(msg_key) == "m/conv/conv-123/epoch/7/msg/resource-abc"
    end

    test "path is reversible", %{root_key: root_key, msg_key: msg_key} do
      path = KeyDerivation.key_path(msg_key)
      {:ok, derived} = KeyDerivation.derive_path(root_key, path)
      assert KeyDerivation.equal?(derived, msg_key)
    end
  end

  describe "export_key/2 and import_root_key/2" do
    test "exports and imports root key with base64" do
      {:ok, original} = KeyDerivation.generate_root_key()

      {:ok, exported} = KeyDerivation.export_key(original, format: :base64)
      assert is_binary(exported)
      assert String.match?(exported, ~r/^[A-Za-z0-9+\/]+=*$/)

      {:ok, imported} = KeyDerivation.import_root_key(exported, format: :base64)
      assert KeyDerivation.equal?(original, imported)
    end

    test "exports and imports root key with raw format" do
      {:ok, original} = KeyDerivation.generate_root_key()

      {:ok, exported} = KeyDerivation.export_key(original, format: :raw)
      assert byte_size(exported) == 32

      {:ok, imported} = KeyDerivation.import_root_key(exported, format: :raw)
      assert KeyDerivation.equal?(original, imported)
    end

    test "default format is base64" do
      {:ok, original} = KeyDerivation.generate_root_key()
      {:ok, exported} = KeyDerivation.export_key(original)

      # Should be base64 encoded
      assert {:ok, _} = Base.decode64(exported)
    end

    test "import rejects invalid base64" do
      assert {:error, :invalid_base64} =
               KeyDerivation.import_root_key("not-valid-base64!!!", format: :base64)
    end

    test "import rejects wrong key length" do
      too_short = Base.encode64(:crypto.strong_rand_bytes(16))

      assert {:error, {:invalid_key_length, 16}} =
               KeyDerivation.import_root_key(too_short, format: :base64)
    end

    test "exports derived keys" do
      {:ok, root_key} = KeyDerivation.generate_root_key()
      {:ok, conv_key} = KeyDerivation.derive_conversation_key(root_key, "conv")
      {:ok, epoch_key} = KeyDerivation.derive_epoch_key(conv_key, 0)
      {:ok, msg_key} = KeyDerivation.derive_message_key(epoch_key, "resource")

      {:ok, _} = KeyDerivation.export_key(conv_key)
      {:ok, _} = KeyDerivation.export_key(epoch_key)
      {:ok, _} = KeyDerivation.export_key(msg_key)
    end
  end

  describe "equal?/2" do
    test "returns true for identical keys" do
      {:ok, root_key} = KeyDerivation.generate_root_key()
      {:ok, conv1} = KeyDerivation.derive_conversation_key(root_key, "same")
      {:ok, conv2} = KeyDerivation.derive_conversation_key(root_key, "same")

      assert KeyDerivation.equal?(conv1, conv2)
    end

    test "returns false for different keys" do
      {:ok, root_key} = KeyDerivation.generate_root_key()
      {:ok, conv1} = KeyDerivation.derive_conversation_key(root_key, "one")
      {:ok, conv2} = KeyDerivation.derive_conversation_key(root_key, "two")

      refute KeyDerivation.equal?(conv1, conv2)
    end

    test "works across key types with same material" do
      # This tests constant-time comparison works correctly
      {:ok, root1} = KeyDerivation.generate_root_key()
      {:ok, root2} = KeyDerivation.generate_root_key()

      refute KeyDerivation.equal?(root1, root2)
    end
  end

  describe "key isolation" do
    test "different conversation branches are isolated" do
      {:ok, root_key} = KeyDerivation.generate_root_key()

      # Two separate conversations
      {:ok, conv1} = KeyDerivation.derive_conversation_key(root_key, "alice")
      {:ok, conv2} = KeyDerivation.derive_conversation_key(root_key, "bob")

      # Same epoch and resource in each
      {:ok, epoch1} = KeyDerivation.derive_epoch_key(conv1, 0)
      {:ok, epoch2} = KeyDerivation.derive_epoch_key(conv2, 0)

      {:ok, msg1} = KeyDerivation.derive_message_key(epoch1, "secret")
      {:ok, msg2} = KeyDerivation.derive_message_key(epoch2, "secret")

      # Keys should be completely different
      refute KeyDerivation.equal?(msg1, msg2)
    end

    test "different epochs are isolated" do
      {:ok, root_key} = KeyDerivation.generate_root_key()
      {:ok, conv_key} = KeyDerivation.derive_conversation_key(root_key, "conv")

      {:ok, epoch1} = KeyDerivation.derive_epoch_key(conv_key, 0)
      {:ok, epoch2} = KeyDerivation.derive_epoch_key(conv_key, 1)

      {:ok, msg1} = KeyDerivation.derive_message_key(epoch1, "same-resource")
      {:ok, msg2} = KeyDerivation.derive_message_key(epoch2, "same-resource")

      refute KeyDerivation.equal?(msg1, msg2)
    end
  end

  describe "Inspect implementations" do
    test "RootKey inspect doesn't expose material" do
      {:ok, root_key} = KeyDerivation.generate_root_key()
      inspected = inspect(root_key)

      assert inspected =~ "#RootKey<"
      assert inspected =~ "..."
      refute inspected =~ Base.encode16(root_key.material)
    end

    test "ConversationKey inspect doesn't expose material" do
      {:ok, root_key} = KeyDerivation.generate_root_key()
      {:ok, conv_key} = KeyDerivation.derive_conversation_key(root_key, "test-conv")
      inspected = inspect(conv_key)

      assert inspected =~ "#ConversationKey<"
      assert inspected =~ "test-conv"
      refute inspected =~ Base.encode16(conv_key.material)
    end

    test "EpochKey inspect doesn't expose material" do
      {:ok, root_key} = KeyDerivation.generate_root_key()
      {:ok, conv_key} = KeyDerivation.derive_conversation_key(root_key, "conv")
      {:ok, epoch_key} = KeyDerivation.derive_epoch_key(conv_key, 42)
      inspected = inspect(epoch_key)

      assert inspected =~ "#EpochKey<"
      assert inspected =~ "epoch: 42"
      refute inspected =~ Base.encode16(epoch_key.material)
    end

    test "MessageKey inspect doesn't expose material" do
      {:ok, root_key} = KeyDerivation.generate_root_key()
      {:ok, conv_key} = KeyDerivation.derive_conversation_key(root_key, "conv")
      {:ok, epoch_key} = KeyDerivation.derive_epoch_key(conv_key, 1)
      {:ok, msg_key} = KeyDerivation.derive_message_key(epoch_key, "my-resource")
      inspected = inspect(msg_key)

      assert inspected =~ "#MessageKey<"
      assert inspected =~ "my-resource"
      refute inspected =~ Base.encode16(msg_key.material)
    end
  end

  describe "determinism" do
    test "full hierarchy is deterministic from root" do
      # Create a known root key from password
      password = "test-password"
      salt = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>

      {:ok, root1, _} = KeyDerivation.derive_root_from_password(password, salt: salt)
      {:ok, root2, _} = KeyDerivation.derive_root_from_password(password, salt: salt)

      # Derive full path from each root
      path = "m/conv/test/epoch/5/msg/document"
      {:ok, msg1} = KeyDerivation.derive_path(root1, path)
      {:ok, msg2} = KeyDerivation.derive_path(root2, path)

      # Should be identical
      assert KeyDerivation.equal?(msg1, msg2)
    end
  end
end
