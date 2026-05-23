# frozen_string_literal: true

require "xoodyak"

RSpec.describe Xoodyak do
  it "has a version number" do
    expect(Xoodyak::VERSION).not_to be nil
  end

  describe "initialization and mode checking" do
    it "initializes in unkeyed mode by default" do
      st = Xoodyak.new
      expect(st).to be_a(Xoodyak)
    end

    it "raises Xoodyak::ArgumentError if nonce, key_id, or counter are passed without key" do
      expect { Xoodyak.new(nonce: "nonce") }.to raise_error(Xoodyak::ArgumentError)
      expect { Xoodyak.new(key_id: "key_id") }.to raise_error(Xoodyak::ArgumentError)
      expect { Xoodyak.new(counter: "counter") }.to raise_error(Xoodyak::ArgumentError)
      expect { Xoodyak.new(counter: "counter") }.to raise_error(Xoodyak::Error)
      expect { Xoodyak.new(counter: "counter") }.to raise_error(::ArgumentError)
    end

    it "raises ArgumentError if too many positional arguments are passed" do
      expect { Xoodyak.new(nil, "nonce") }.to raise_error(::ArgumentError)
    end

    it "initializes in keyed mode when key is provided" do
      st = Xoodyak.new("key")
      expect(st).to be_a(Xoodyak)
    end
  end

  describe "unkeyed mode (hashing)" do
    it "matches empty squeeze test vector" do
      st = Xoodyak.new
      out = st.squeeze(32)
      expected = [
        141, 216, 213, 137, 191, 252, 99, 169, 25, 45, 35, 27, 20, 160, 165, 255, 204, 246,
        41, 214, 87, 39, 76, 114, 39, 130, 131, 52, 124, 189, 128, 53
      ].pack("C*")
      expect(out).to eq(expected)
    end

    it "matches unkeyed absorb and squeeze test vector" do
      st = Xoodyak.new
      m = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. " \
          "Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, " \
          "when an unknown printer took a galley of type and scrambled it to make a type specimen book. " \
          "It has survived not only five centuries, but also the leap into electronic typesetting, " \
          "remaining essentially unchanged. It was popularised in the 1960s with the release of " \
          "Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing " \
          "software like Aldus PageMaker including versions of Lorem Ipsum."
      st.absorb(m)
      hash = st.squeeze(32)
      expected = [
        144, 82, 141, 27, 59, 215, 34, 104, 197, 106, 251, 142, 112, 235, 111, 168, 19, 6,
        112, 222, 160, 168, 230, 38, 27, 229, 248, 179, 94, 227, 247, 25
      ].pack("C*")
      expect(hash).to eq(expected)
    end

    it "raises error if encrypt or decrypt are called in unkeyed mode" do
      st = Xoodyak.new
      expect { st.encrypt("msg") }.to raise_error(Xoodyak::KeyedModeError)
      expect { st.decrypt("msg") }.to raise_error(Xoodyak::KeyedModeError)
      expect { st.aead_encrypt("msg") }.to raise_error(Xoodyak::KeyedModeError)
      expect { st.aead_decrypt("msg") }.to raise_error(Xoodyak::KeyedModeError)
      expect { st.aead_encrypt_detached("msg") }.to raise_error(Xoodyak::KeyedModeError)
      expect { st.aead_decrypt_detached("msg", "tag") }.to raise_error(Xoodyak::KeyedModeError)
      expect { st.ratchet }.to raise_error(Xoodyak::KeyedModeError)
      expect { st.encrypt("msg") }.to raise_error(Xoodyak::Error)
    end
  end

  describe "keyed mode" do
    it "matches keyed empty squeeze test vector" do
      st = Xoodyak.new("key")
      out = st.squeeze(32)
      expected = [
        106, 247, 180, 176, 207, 217, 130, 200, 237, 113, 163, 185, 224, 53, 120, 137, 251,
        126, 216, 3, 87, 45, 239, 214, 41, 201, 246, 56, 83, 55, 18, 108
      ].pack("C*")
      expect(out).to eq(expected)
    end

    it "can encrypt and decrypt plaintext" do
      st = Xoodyak.new("key")
      plaintext = "hello world"
      ciphertext = st.encrypt(plaintext)
      expect(ciphertext).not_to eq(plaintext)

      # Decrypt using a cloned state to show it works
      st2 = Xoodyak.new("key")
      decrypted = st2.decrypt(ciphertext)
      expect(decrypted).to eq(plaintext)
    end

    it "raises decryption error on invalid tag mismatch" do
      st = Xoodyak.new("key")
      st.absorb("ad")
      ct = st.aead_encrypt("message")

      st2 = Xoodyak.new("key")
      st2.absorb("wrong_ad")
      expect { st2.dup.aead_decrypt(ct) }.to raise_error(Xoodyak::VerificationError)
      expect { st2.dup.aead_decrypt(ct) }.to raise_error(Xoodyak::Error)
    end

    it "supports detached AEAD encrypt and decrypt" do
      nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15].pack("C*")
      st = Xoodyak.new("key", nonce: nonce)
      st.absorb("ad")

      ct, tag = st.aead_encrypt_detached("message")
      expected_tag = [
        12, 91, 0, 120, 191, 214, 119, 66, 122, 225, 184, 239, 213, 214, 247, 57
      ].pack("C*")
      expect(tag).to eq(expected_tag)

      st2 = Xoodyak.new("key", nonce: nonce)
      st2.absorb("ad")
      decrypted = st2.aead_decrypt_detached(ct, tag)
      expect(decrypted).to eq("message")
    end

    it "raises Xoodyak::ArgumentError on aead_decrypt when ciphertext is too short" do
      st = Xoodyak.new("key")
      expect { st.aead_decrypt("short") }.to raise_error(Xoodyak::ArgumentError)
    end

    it "raises Xoodyak::ArgumentError on aead_decrypt_detached when tag is not 16 bytes" do
      st = Xoodyak.new("key")
      expect { st.aead_decrypt_detached("msg", "short_tag") }.to raise_error(Xoodyak::ArgumentError)
    end

    it "raises Xoodyak::VerificationError on aead_decrypt_detached when tag is invalid" do
      nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15].pack("C*")
      st = Xoodyak.new("key", nonce: nonce)
      st.absorb("ad")
      ct, tag = st.aead_encrypt_detached("message")

      st2 = Xoodyak.new("key", nonce: nonce)
      st2.absorb("ad")

      tampered_tag = tag.dup
      tampered_tag.setbyte(0, tampered_tag.getbyte(0) ^ 1)

      expect { st2.dup.aead_decrypt_detached(ct, tampered_tag) }.to raise_error(Xoodyak::VerificationError)
      expect { st2.dup.aead_decrypt_detached(ct, tampered_tag) }.to raise_error(Xoodyak::Error)
    end

    it "can ratchet the state" do
      st = Xoodyak.new("key")
      st.ratchet
      expect { st.squeeze(16) }.not_to raise_error
    end
  end

  describe "duplication" do
    it "duplicates unkeyed state correctly" do
      st = Xoodyak.new
      st.absorb("msg")
      st2 = st.dup

      expect(st.squeeze(32)).to eq(st2.squeeze(32))
    end

    it "duplicates keyed state correctly" do
      st = Xoodyak.new("key")
      st.absorb("ad")
      st2 = st.dup

      expect(st.squeeze(32)).to eq(st2.squeeze(32))
    end

    it "supports cloning with freeze settings" do
      st = Xoodyak.new
      expect(st.clone).not_to be_frozen
      expect(st.clone(freeze: true)).to be_frozen
    end

    it "supports subclassing and duplicates subclass state and class type" do
      subclass = Class.new(Xoodyak) do
        attr_accessor :custom_val
      end
      st = subclass.new
      st.custom_val = 42
      st.absorb("msg")

      st2 = st.dup
      expect(st2).to be_a(subclass)
      expect(st2.custom_val).to eq(42)
      expect(st.squeeze(32)).to eq(st2.squeeze(32))
    end
  end

  describe "Digest interface integration" do
    it "inherits from Digest::Base" do
      expect(Xoodyak::Digest.ancestors).to include(Digest::Base)
    end

    it "computes digest matching empty hash test vector" do
      d = Xoodyak::Digest.new
      expected_hex = [
        141, 216, 213, 137, 191, 252, 99, 169, 25, 45, 35, 27, 20, 160, 165, 255, 204, 246,
        41, 214, 87, 39, 76, 114, 39, 130, 131, 52, 124, 189, 128, 53
      ].map { |x| x.to_s(16).rjust(2, "0") }.join
      expect(d.hexdigest).to eq(expected_hex)
    end

    it "computes digest using update" do
      m = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. " \
          "Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, " \
          "when an unknown printer took a galley of type and scrambled it to make a type specimen book. " \
          "It has survived not only five centuries, but also the leap into electronic typesetting, " \
          "remaining essentially unchanged. It was popularised in the 1960s with the release of " \
          "Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing " \
          "software like Aldus PageMaker including versions of Lorem Ipsum."
      d = Xoodyak::Digest.new
      d.update(m)
      expected_hex = [
        144, 82, 141, 27, 59, 215, 34, 104, 197, 106, 251, 142, 112, 235, 111, 168, 19, 6,
        112, 222, 160, 168, 230, 38, 27, 229, 248, 179, 94, 227, 247, 25
      ].map { |x| x.to_s(16).rjust(2, "0") }.join
      expect(d.hexdigest).to eq(expected_hex)
    end

    it "computes correct digest for multiple updates compared to single update" do
      m1 = "Lorem Ipsum is simply dummy text "
      m2 = "of the printing and typesetting industry."

      d = Xoodyak::Digest.new
      d.update(m1)
      d.update(m2)

      expected = Xoodyak::Digest.new.update(m1 + m2).hexdigest
      expect(d.hexdigest).to eq(expected)
    end

    it "resets state correctly" do
      d = Xoodyak::Digest.new
      d.update("something")
      d.reset
      expected_hex = [
        141, 216, 213, 137, 191, 252, 99, 169, 25, 45, 35, 27, 20, 160, 165, 255, 204, 246,
        41, 214, 87, 39, 76, 114, 39, 130, 131, 52, 124, 189, 128, 53
      ].map { |x| x.to_s(16).rjust(2, "0") }.join
      expect(d.hexdigest).to eq(expected_hex)
    end

    it "duplicates digest state using dup/clone" do
      d = Xoodyak::Digest.new
      d.update("hello")
      d2 = d.dup
      d.update(" world")
      d2.update(" world")
      expect(d.hexdigest).to eq(d2.hexdigest)
    end

    it "can load dynamically via Digest helper" do
      expect(Digest("Xoodyak")).to eq(Xoodyak::Digest)
      expect(Digest::Xoodyak).to eq(Xoodyak::Digest)
    end
  end
end
