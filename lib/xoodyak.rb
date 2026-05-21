# frozen_string_literal: true

require "digest"

# Define the Digest class in the Xoodyak namespace inheriting from Digest::Base,
# so the C extension can successfully find it and attach the digest metadata.
class Xoodyak
  class Digest < ::Digest::Base
  end
end

require_relative "xoodyak/version"

begin
  RUBY_VERSION =~ /(\d+\.\d+)/
  require "xoodyak/#{Regexp.last_match(1)}/xoodyak"
rescue LoadError
  begin
    require_relative "xoodyak/xoodyak"
  rescue LoadError
    require "xoodyak/xoodyak"
  end
end

module Digest
  Xoodyak = ::Xoodyak::Digest
end

