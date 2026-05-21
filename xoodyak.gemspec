# frozen_string_literal: true

require_relative "lib/xoodyak/version"

Gem::Specification.new do |spec|
  spec.name = "xoodyak"
  spec.version = Xoodyak::VERSION
  spec.author = 'Sarun Rattanasiri'
  spec.email = 'midnight_w@gmx.tw'

  spec.summary = "A fast, memory-safe Rust-backed Ruby implementation of the Xoodyak cryptographic scheme"
  spec.description = "A Ruby wrapper for the Xoodyak cryptographic scheme, built in Rust using magnus and rb-sys. " \
                     "It supports hashing (unkeyed mode), symmetric encryption and AEAD (keyed mode), " \
                     "forward secrecy (state ratcheting), and integrates with the standard Ruby Digest API."
  spec.homepage = "https://github.com/midnight-wonderer/xoodyak-rb"
  spec.required_ruby_version = ">= 3.2.0"
  spec.license = "BSD-2-Clause"

  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"

  spec.files = Dir["LICENSE.md", "README.md", "lib/**/*", "ext/**/*", "sig/**/*"].reject do |f|
    File.directory?(f) || f.end_with?(".so") || f.end_with?(".bundle")
  end
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/xoodyak/extconf.rb"]

  spec.add_dependency "rb_sys", "~> 0.9.91"
end
