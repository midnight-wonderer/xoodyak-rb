# Xoodyak Ruby Gem

<div align="center">
  <h1>Xoodyak for Ruby 💎</h1>
  <p><strong>A blazing fast, secure, and modern Rust-backed Ruby implementation of the Xoodyak cryptographic scheme</strong></p>

  <a href="https://github.com/midnight-wonderer/xoodyak-rb/actions"><img src="https://img.shields.io/github/actions/workflow/status/midnight-wonderer/xoodyak-rb/main.yml?branch=main&style=flat-square" alt="CI Status"></a>
  <a href="https://badge.fury.io/rb/xoodyak"><img src="https://img.shields.io/gem/v/xoodyak.svg?style=flat-square" alt="Gem Version"></a>
  <a href="LICENSE.md"><img src="https://img.shields.io/badge/license-BSD--2--Clause-blue.svg?style=flat-square" alt="License"></a>
  <a href="sig/xoodyak.rbs"><img src="https://img.shields.io/badge/types-RBS-informational.svg?style=flat-square" alt="RBS Types"></a>
</div>

---

## 📖 Table of Contents

- [Introduction](#-introduction)
- [Features](#-features)
- [Installation](#-installation)
- [Usage Guide](#-usage-guide)
  - [1. Hashing (Unkeyed Mode)](#1-hashing-unkeyed-mode)
  - [2. Ruby Digest API Integration](#2-ruby-digest-api-integration)
  - [3. Symmetric Encryption (Keyed Mode)](#3-symmetric-encryption-keyed-mode)
  - [4. Authenticated Encryption (AEAD)](#4-authenticated-encryption-aead)
    - [Combined Ciphertext & Tag](#combined-ciphertext--tag)
    - [Detached Ciphertext & Tag](#detached-ciphertext--tag)
  - [5. Advanced Keyed Customization (Nonces, Key IDs, Counters)](#5-advanced-keyed-customization-nonces-key-ids-counters)
  - [6. Forward Secrecy (State Ratcheting)](#6-forward-secrecy-state-ratcheting)
  - [7. Stateful Session-based Encrypt/Decrypt](#7-stateful-session-based-encryptdecrypt)
  - [8. State Cloning & Checkpointing](#8-state-cloning--checkpointing)
- [API Reference](#-api-reference)
- [Type Safety with RBS](#-type-safety-with-rbs)
- [Development & Testing](#-development--testing)
- [License](#-license)

---

## 🌟 Introduction

**Xoodyak** is a lightweight cryptographic scheme designed by the Keccak team (creators of SHA-3). It is part of the Keccak family and is optimized for low-resource environments. Xoodyak operates as a stateful "sponge" construction, making it extremely versatile. A single instance can perform:
- **Hashing** (unkeyed mode)
- **Symmetric Encryption** (keyed mode)
- **Message Authentication Codes (MAC)** (keyed mode)
- **Authenticated Encryption with Associated Data (AEAD)** (keyed mode)
- **Key Derivation & Ratcheting**

This gem provides a production-ready Ruby interface to Xoodyak, wrapping a highly optimized Rust implementation.

---

## ⚡ Features

- 🏎️ **Blazing Fast**: Native Rust extension using `magnus` and `rb-sys` outpaces pure Ruby cryptography.
- 🔒 **Sponge-based Design**: Supports stateful session-based protocols.
- 🛠️ **Seamless Digest Integration**: Inherits from Ruby's standard `Digest::Base` for drop-in compatibility.
- 📦 **Zero-Configuration AEAD**: Simple combined and detached AEAD interfaces.
- 🧩 **RBS Typed**: Complete type definitions shipped out of the box.
- 🛡️ **Memory Safe**: Built-in Rust safety guarantees prevent common memory leaks and buffer overflows.

---

## 📥 Installation

Add this line to your application's Gemfile:

```ruby
gem 'xoodyak'
```

And then execute:

```bash
$ bundle install
```

Or install it directly via:

```bash
$ gem install xoodyak
```

> [!NOTE]
> Since this gem includes a Rust extension, you must have the **Rust toolchain** (cargo/rustc) installed on your system to compile it.

---

## 🚀 Usage Guide

### 1. Hashing (Unkeyed Mode)

In unkeyed mode, Xoodyak acts as a standard cryptographic hash function. You can feed data incrementally using `absorb` and extract the hash using `squeeze`.

```ruby
require 'xoodyak'

# Initialize in unkeyed (hashing) mode
hash_sponge = Xoodyak.new

# Absorb data
hash_sponge.absorb("Hello, world!")

# Squeeze out the digest (you can request any length!)
digest = hash_sponge.squeeze(32)
# => returns a 32-byte binary string
```

### 2. Ruby Digest API Integration

For standard hashing tasks, this gem integrates directly with Ruby's `Digest` framework.

```ruby
require 'xoodyak'

# 1. Instantiate the Digest class
digest = Xoodyak::Digest.new
digest.update("Hello, ")
digest.update("world!")
puts digest.hexdigest
# => "c1ae6b98..."

# 2. Or use the shortcut methods
hex_hash = Digest::Xoodyak.hexdigest("Hello, world!")
binary_hash = Digest::Xoodyak.digest("Hello, world!")

# 3. Dynamic loading also works
algo = Digest("Xoodyak").new
```

### 3. Symmetric Encryption (Keyed Mode)

By passing a key during initialization, Xoodyak enters **keyed mode**. This allows standard symmetric encryption and decryption.

```ruby
require 'xoodyak'

key = "my-secure-key-16" # Can be any length (Xoodyak handles varying key lengths)

# Encrypting
encryptor = Xoodyak.new(key)
ciphertext = encryptor.encrypt("super secret message")

# Decrypting (initialize a new state with the same key)
decryptor = Xoodyak.new(key)
plaintext = decryptor.decrypt(ciphertext)
puts plaintext # => "super secret message"
```

### 4. Authenticated Encryption (AEAD)

Standard encryption protects confidentiality but not integrity. **AEAD** (Authenticated Encryption with Associated Data) is highly recommended because it also authenticates the message and optional "Associated Data" (like unencrypted routing headers).

#### Combined Ciphertext & Tag

`aead_encrypt` appends a 16-byte authentication tag directly to the ciphertext. `aead_decrypt` verifies the tag and returns the decrypted text, raising an error if the tag is invalid.

```ruby
require 'xoodyak'
require 'securerandom'

key = "my-secure-key-16"
nonce = SecureRandom.bytes(16) # Nonces must be unique for each encryption!

# Encrypt with Associated Data
alice = Xoodyak.new(key, nonce)
alice.absorb("Associated Data (unencrypted header)")
ciphertext_with_tag = alice.aead_encrypt("confidential message")

# Decrypt and Verify
bob = Xoodyak.new(key, nonce)
bob.absorb("Associated Data (unencrypted header)") # Must match Alice's AD

begin
  decrypted = bob.aead_decrypt(ciphertext_with_tag)
  puts decrypted # => "confidential message"
rescue Xoodyak::Error => e
  # Raised if ciphertext or associated data was altered
  puts "Integrity check failed: #{e.message}"
end
```

#### Detached Ciphertext & Tag

If your protocol stores or transmits the ciphertext and tag separately, you can use the detached API:

```ruby
require 'xoodyak'
require 'securerandom'

key = "my-secure-key-16"
nonce = SecureRandom.bytes(16)

# Encrypt
alice = Xoodyak.new(key, nonce)
alice.absorb("metadata")
ciphertext, tag = alice.aead_encrypt_detached("confidential message")

# Decrypt and Verify
bob = Xoodyak.new(key, nonce)
bob.absorb("metadata")

begin
  decrypted = bob.aead_decrypt_detached(ciphertext, tag)
  puts decrypted # => "confidential message"
rescue Xoodyak::Error => e
  puts "Integrity check failed: #{e.message}"
end
```

### 5. Advanced Keyed Customization (Nonces, Key IDs, Counters)

Xoodyak supports initializing the keyed state with a variety of optional parameters:
- `key` (required for keyed mode)
- `nonce` (optional binary string)
- `key_id` (optional binary string)
- `counter` (optional binary string)

```ruby
# Initialize with key, nonce, key_id, and counter
xoodyak = Xoodyak.new(key, nonce, key_id, counter)
```

> [!WARNING]
> Passing `nonce`, `key_id`, or `counter` without a `key` will raise an `ArgumentError`.

### 6. Forward Secrecy (State Ratcheting)

State ratcheting advances the keyed state in a non-reversible way. Even if an attacker gains access to the current state, they cannot reconstruct past states, providing forward secrecy.

```ruby
require 'xoodyak'

xoodyak = Xoodyak.new("my-secret-key")

# Perform operations...
xoodyak.absorb("some context")

# Ratchet the state
xoodyak.ratchet

# Squeeze out session keys or continue encrypting
session_key = xoodyak.squeeze(32)
```

### 7. Stateful Session-based Encrypt/Decrypt

Xoodyak is stateful: every operation transitions the internal sponge state. This allows Bob and Alice to have a stateful session where they encrypt and decrypt a stream of messages in order.

```ruby
require 'xoodyak'
require 'securerandom'

key = "session-key-1234"
nonce = SecureRandom.bytes(16)

alice = Xoodyak.new(key, nonce)
bob = Xoodyak.new(key, nonce)

# Alice sends first message
ct1 = alice.encrypt("Message 1")
# Bob receives and decrypts
puts bob.decrypt(ct1) # => "Message 1"

# Alice sends second message (depends on state mutated by msg1!)
ct2 = alice.encrypt("Message 2")
# Bob decrypts
puts bob.decrypt(ct2) # => "Message 2"
```

> [!IMPORTANT]
> Because the state mutates with each operation, Alice and Bob must remain in perfect sync. If any message is lost, reordered, or duplicated, decryption will fail. This provides built-in replay and out-of-order protection.

### 8. State Cloning & Checkpointing

You can duplicate or clone the state of a Xoodyak instance. This is useful for saving checkpoints or branching a cryptographic session.

```ruby
require 'xoodyak'

xoodyak = Xoodyak.new
xoodyak.absorb("initial setup data")

# Duplicate the state
checkpoint = xoodyak.dup

# Both instances can now diverge independently
xoodyak.absorb("branch A")
checkpoint.absorb("branch B")

puts xoodyak.squeeze(16).unpack1("H*")      # Squeezes based on "initial setup data" + "branch A"
puts checkpoint.squeeze(16).unpack1("H*")   # Squeezes based on "initial setup data" + "branch B"
```

---

## 🛠️ API Reference

### `Xoodyak` Class

| Method | Signature | Mode | Description |
| :--- | :--- | :--- | :--- |
| `initialize` | `(key=nil, nonce=nil, key_id=nil, counter=nil)` | Any | Creates a Xoodyak instance. Enters keyed mode if a key is provided. |
| `absorb` | `(bin: String) -> void` | Any | Absorbs binary data into the state. |
| `squeeze` | `(len: Integer) -> String` | Any | Squeezes `len` bytes from the state. |
| `squeeze_key` | `(len: Integer) -> String` | Any | Squeezes `len` key bytes from the state. |
| `encrypt` | `(bin: String) -> String` | Keyed | Encrypts a message. |
| `decrypt` | `(bin: String) -> String` | Keyed | Decrypts a message. |
| `aead_encrypt` | `(bin: String) -> String` | Keyed | Encrypts a message, appending a 16-byte authentication tag. |
| `aead_decrypt` | `(bin: String) -> String` | Keyed | Verifies the tag and decrypts a combined AEAD message. |
| `aead_encrypt_detached` | `(bin: String) -> [String, String]` | Keyed | Encrypts a message, returning `[ciphertext, tag]`. |
| `aead_decrypt_detached` | `(bin: String, tag: String) -> String` | Keyed | Verifies the detached tag and decrypts the ciphertext. |
| `ratchet` | `() -> void` | Keyed | Ratchets the state to provide forward secrecy. |
| `dup` / `clone` | `() -> Xoodyak` | Any | Creates a deep copy of the Xoodyak instance state. |

---

## 🧩 Type Safety with RBS

This gem is packaged with complete RBS type definitions. You can typecheck your application using Steep or other Ruby signature verification tools.

Type signatures are defined in [sig/xoodyak.rbs](file:///storage/projects/xoodyak-rb/sig/xoodyak.rbs).

---

## 🔧 Development & Testing

After checking out the repo, run `bin/setup` to install dependencies.

### Compilation

Since the core cryptographic operations are written in Rust, you must compile the C-extension locally:

```bash
bundle exec rake compile
```

### Running Tests

Run the RSpec test suite:

```bash
bundle exec rake spec
```

### Linting

Check code formatting and style guidelines:

```bash
bundle exec rake rubocop
```

---

## 📄 License

This gem is available as open source under the terms of the [BSD 2-Clause License](LICENSE.md).
