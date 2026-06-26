# frozen_string_literal: true

require_relative "builtins/codecs/json_decoder"

module Ruby
  module Rego
    # Public, layer-neutral name for the strict number-preserving JSON decoder. The implementation lives
    # under Builtins::Codecs (it is the engine for json.unmarshal / json.is_valid / io.jwt.decode), but
    # the rego-validate CLI loads JSON input/data through it too. The CLI is the application layer and must
    # not reach into a Builtins:: internal path, so it binds to this alias instead — a single point of
    # coupling if the implementation is ever relocated.
    JsonDecoder = Builtins::Codecs::JsonDecoder
  end
end
