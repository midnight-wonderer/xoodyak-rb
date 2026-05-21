# frozen_string_literal: true

RSpec.describe Xoodyak do
  it "has a version number" do
    expect(Xoodyak::VERSION).not_to be nil
  end

  it "can call into Rust" do
    result = Xoodyak.hello("world")

    expect(result).to be("Hello earth, from Rust!")
  end
end
