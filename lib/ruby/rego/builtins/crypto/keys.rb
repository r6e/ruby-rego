# frozen_string_literal: true

require "base64"
require "openssl"

module Ruby
  module Rego
    module Builtins
      # Private-key parsing builtins, reopening Crypto so they share string_value and the
      # registration wiring. Both are OpenSSL-backed and total (any parse failure yields undefined
      # or null, never an exception), and both faithfully reproduce OPA's topdown/crypto.go logic —
      # a thin wrapper over Go's x509 PEM-block parsing (getPrivateKeysFromPEMData):
      #
      #   crypto.parse_private_keys(s)
      #     "" -> null; otherwise scan every PEM block, parsing the three private-key block types
      #     (RSA/PKCS8/EC) and SILENTLY SKIPPING any other type (e.g. CERTIFICATE). A recognized
      #     block that fails to parse — or holds a key type Go's x509 does not support — makes the
      #     whole call undefined; zero keys yields []. Each key is marshalled to its Go encoding/json
      #     shape: rsa.PrivateKey / ecdsa.PrivateKey objects, std-base64 for Ed25519, {} for X25519.
      #
      #   crypto.x509.parse_rsa_private_key(s)  (despite the name, any key type -> a JWK)
      #     "" -> undefined; a non-"-----BEGIN" string is std-base64-decoded first (invalid base64 ->
      #     undefined). The SAME block scan (which itself std-base64-decodes a valid-base64 input)
      #     then runs, so OPA accepts a doubly-base64-encoded PEM here but not via parse_private_keys
      #     — a faithful side effect of composing the two decode steps. The FIRST key becomes a JWK.
      #     Zero keys -> null; a first key the JWK encoding does not cover (e.g. a P-224 curve) -> undefined.
      #
      # The set of supported key types mirrors Go exactly: x509 accepts RSA, Ed25519, X25519, and EC
      # on the four crypto/elliptic curves (P-224/256/384/521) — but the JWK encoding omits P-224
      # (no JOSE registration). DSA, Ed448, X448 and non-NIST EC curves are unsupported -> undefined.
      # rubocop:disable Metrics/ModuleLength
      # :reek:TooManyConstants -- the pem.Decode marker sentinels are a faithful port of Go's constants.
      module Crypto
        # PEM block types getPrivateKeysFromPEMData parses; every other type is skipped, not failed.
        RECOGNIZED_KEY_BLOCKS = ["RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY"].freeze

        # The pem.Decode marker sentinels (Go's pemStart / pemEnd / pemEndOfLine), with and without
        # the leading newline that anchors a marker to the start of a line.
        PEM_START = "\n-----BEGIN "
        PEM_START_NOLF = "-----BEGIN "
        PEM_END = "\n-----END "
        PEM_END_NOLF = "-----END "
        PEM_EOL = "-----"

        # The bytes Go's base64 decoder treats as insignificant (removeSpacesAndTabs strips " \t"; the
        # decoder ignores "\r\n"), and the complement of the std-base64 alphabet (plus padding and
        # those skip bytes) — a byte matching it inside a block body dooms the decode.
        BASE64_SKIP = " \t\r\n"
        NON_BASE64_BYTE = %r{[^A-Za-z0-9+/= \t\r\n]}

        # JWK "crv" names (RFC 7518) for the curves the JWK encoding covers (P-224 is excluded).
        EC_CURVE_NAMES = {
          "prime256v1" => "P-256",
          "secp384r1" => "P-384",
          "secp521r1" => "P-521"
        }.freeze

        # The EC curves Go's crypto/elliptic supports (so x509 parses them): the JWK curves plus
        # P-224, which the Go-struct output handles even though the JWK encoding does not.
        EC_STRUCT_CURVES = (EC_CURVE_NAMES.keys + ["secp224r1"]).freeze

        # Go dispatches each PEM block type to ONE x509 parser (PKCS#1 / PKCS#8 / SEC1), so a DER in
        # the wrong format for its label is rejected even though OpenSSL's format-agnostic reader would
        # accept it. The three formats are distinguished by their second ASN.1 element: PKCS#1's is the
        # modulus INTEGER, PKCS#8's is the algorithm SEQUENCE, SEC1's is the private-key OCTET STRING.
        BLOCK_FORMAT_ELEMENT = {
          "RSA PRIVATE KEY" => OpenSSL::ASN1::Integer,
          "PRIVATE KEY" => OpenSSL::ASN1::Sequence,
          "EC PRIVATE KEY" => OpenSSL::ASN1::OctetString
        }.freeze

        # Upper bound on the leading ASN.1 element a block may parse to before OpenSSL::PKey.read is
        # attempted (DoS guard — see read_key). 64 KiB is far above any real private key (an RSA-16384
        # DER is ~9 KB), so only an absurd >130K-bit key would exceed it.
        MAX_KEY_DER_BYTES = 64 * 1024

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::Value]
        # :reek:TooManyStatements -- a faithful port of OPA's builtinCryptoParsePrivateKeys flow.
        # :reek:NilCheck -- nil is supported_keys's "a recognized block failed or is unsupported" sentinel.
        def self.parse_private_keys(value)
          string = string_value(value, "crypto.parse_private_keys")
          return UndefinedValue.new unless scannable?(string)
          return NullValue.new if string.empty?

          keys = supported_keys(string)
          return UndefinedValue.new if keys.nil?

          Value.from_ruby(keys.map { |key| go_struct_for(key) })
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::Value]
        # :reek:TooManyStatements -- a faithful port of OPA's builtinCryptoJWKFromPrivateKey flow.
        # :reek:NilCheck -- nil sentinels: bad base64/failed block (undefined), JWK-unsupported key (undefined).
        # rubocop:disable Metrics/AbcSize
        def self.parse_rsa_private_key(value)
          string = string_value(value, "crypto.x509.parse_rsa_private_key")
          return UndefinedValue.new if !scannable?(string) || string.empty?

          pem = pem_or_base64(string)
          return UndefinedValue.new if pem.nil?

          keys = supported_keys(pem)
          return UndefinedValue.new if keys.nil?
          return NullValue.new if keys.empty?

          jwk = jwk_for(keys.first)
          jwk.nil? ? UndefinedValue.new : Value.from_ruby(jwk)
        end
        # rubocop:enable Metrics/AbcSize

        # OPA's parse_rsa_private_key takes PEM directly or a std-base64-encoded DER; a non-PEM string
        # that is not valid base64 is the error case (nil -> undefined).
        # :reek:UncommunicativeMethodName -- "PEM or base64" is the precise accepted-input description.
        def self.pem_or_base64(string)
          return string if string.start_with?("-----BEGIN")

          std_base64_decode(string)
        end
        private_class_method :pem_or_base64

        # Decode every PEM block to [type, DER] (skipping the rest), parse the recognized private-key
        # types, and keep only keys whose type Go's x509 supports. Returns the parsed keys, or nil if
        # a recognized block fails to parse or holds an unsupported key type (OPA -> undefined).
        # :reek:TooManyStatements -- the block scan + parse + type-gate loop reads clearest inline.
        # :reek:NilCheck -- read_key's nil return is the recognized-block-failed sentinel.
        def self.supported_keys(pem)
          keys = [] # : Array[untyped]
          pem_blocks(pem).each do |type, der|
            next unless RECOGNIZED_KEY_BLOCKS.include?(type)

            key = read_key(type, der)
            return nil if key.nil? || !go_supported?(key)

            keys << key
          end
          keys
        end
        private_class_method :supported_keys

        # Extract each PEM block as [type, der_bytes], reproducing OPA's getPrivateKeysFromPEMData: the
        # whole input is std-base64-decoded first when it is valid base64 (so a base64-of-PEM is scanned
        # as PEM), then pem.Decode runs in a loop. The fast-path guard plus the cursor (no per-iteration
        # string copies) and pem_decode's cached END keep scanning linear even on adversarial input.
        # :reek:TooManyStatements -- the prepare + decode loop read clearest together.
        def self.pem_blocks(pem)
          data = pem.b
          data = std_base64_decode(data) || data
          return [] unless data.include?(PEM_END_NOLF)

          blocks = [] # : Array[[String, String]]
          pos = 0
          while (decoded = pem_decode(data, pos))
            type, der, pos = decoded
            blocks << [type, der]
          end
          blocks
        end
        private_class_method :pem_blocks

        # std-base64 (Go's base64.StdEncoding.DecodeString): ignores "\r\n", rejects spaces/tabs; nil
        # on invalid input.
        def self.std_base64_decode(string)
          Base64.strict_decode64(string.delete("\r\n"))
        rescue ArgumentError
          nil
        end
        private_class_method :std_base64_decode

        # A cursor-based port of Go's encoding/pem.Decode: scans `data` from `start`, returning
        # [type, der, next_pos] for the next valid block or nil when none remains. Faithful to every
        # framing rule (line-leading markers, getLine's trailing-" \t" trim, the RFC 1421 header
        # section, END-trailer validation, removeSpacesAndTabs). `end_at` caches the next END position
        # so a BEGIN that fails and retries an interior BEGIN does not re-scan to a distant END.
        # rubocop:disable Metrics/AbcSize, Metrics/MethodLength, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
        # :reek:TooManyStatements -- a verbatim port of pem.Decode's single state-machine loop.
        def self.pem_decode(data, start)
          pos = start
          end_at = nil # : Integer?
          marker = PEM_START_NOLF.length
          loop do
            if data[pos, marker] == PEM_START_NOLF
              pos += marker
            elsif (found = data.index(PEM_START, pos))
              pos = found + PEM_START.length
            else
              return nil
            end

            type_line, pos = get_line(data, pos)
            next unless type_line.end_with?(PEM_EOL)

            type = type_line[0...(type_line.length - PEM_EOL.length)].to_s
            body_pos, any_headers = skip_headers(data, pos) || (return nil)
            end_index, trailer_index, end_at = locate_end(data, body_pos, any_headers, end_at)
            block = (close_block(data, body_pos, end_index, trailer_index, type) if end_index && trailer_index)
            return [type, block[0], block[1]] if block

            pos = body_pos
          end
        end
        # rubocop:enable Metrics/AbcSize, Metrics/MethodLength, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
        private_class_method :pem_decode

        # Find the END line for a block body at `body_pos`. Returns [end_index, trailer_index, end_at]
        # where end_index/trailer_index are nil if no line-anchored END follows. `end_at` is the cached
        # "\n-----END " search state — nil (not searched), -1 (searched, none ahead), or a position —
        # carried forward so the BEGIN-retry loop never re-scans: since body_pos only advances, once no
        # anchored END exists ahead, none ever will, so the -1 short-circuits every later search.
        # :reek:TooManyStatements -- the immediate-END vs cached-search branch reads clearest inline.
        # :reek:NilCheck -- end_at's nil means "cache empty, must search".
        # :reek:LongParameterList -- the body position, header flag, and cache are all the END search needs.
        # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
        def self.locate_end(data, body_pos, any_headers, end_at)
          end_len = PEM_END.length
          if !any_headers && data[body_pos, PEM_END_NOLF.length] == PEM_END_NOLF
            return [body_pos, body_pos + end_len - 1, end_at]
          end

          end_at = data.index(PEM_END, body_pos) || -1 if end_at.nil? || (end_at >= 0 && end_at < body_pos)
          found = end_at.negative? ? nil : end_at
          [found, found && (found + end_len), end_at]
        end
        # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
        private_class_method :locate_end

        # Validate the END line's trailer and decode the block body between `body_start` and the END.
        # Returns [der, next_pos] or nil to abandon this BEGIN (Go's `continue`).
        # rubocop:disable Metrics/AbcSize
        # :reek:TooManyStatements -- the second half of pem.Decode; kept whole for fidelity.
        # :reek:LongParameterList -- the slice bounds and type are all needed to validate the END line.
        def self.close_block(data, body_start, end_index, trailer_index, type)
          trailer_len = type.length + PEM_EOL.length
          rest_of_line = trailer_index + trailer_len
          return nil if rest_of_line > data.length

          trailer = data[trailer_index, trailer_len].to_s
          return nil unless trailer.start_with?(type) && trailer.end_with?(PEM_EOL)
          return nil unless get_line(data, rest_of_line).first.empty?

          der = decode_region(data, body_start, end_index) || (return nil)
          [der, get_line(data, end_index + PEM_END.length - 1).last]
        end
        private_class_method :close_block
        # rubocop:enable Metrics/AbcSize

        # Port of Go's getLine on a cursor: returns the line at `pos` with its trailing CR and trailing
        # " \t" trimmed, and the position just past the newline.
        # :reek:TooManyStatements -- a faithful port of getLine's index arithmetic.
        # :reek:NilCheck -- a nil newline means "no more newlines: the line runs to end of input".
        def self.get_line(data, pos)
          newline = data.index("\n", pos)
          if newline.nil?
            ending = data.length
            return [trimmed_line(data, pos, ending), ending]
          end

          prev = newline - 1
          line_end = newline > pos && data[prev] == "\r" ? prev : newline
          [trimmed_line(data, pos, line_end), newline + 1]
        end
        private_class_method :get_line

        # The slice data[from...upto] with Go getLine's trailing " \t" trimmed.
        def self.trimmed_line(data, from, upto)
          data[from...upto].to_s.sub(/[ \t]+\z/, "")
        end
        private_class_method :trimmed_line

        # Port of pem.Decode's header loop: consume the leading "key: value" lines (RFC 1421 headers)
        # from `pos` and return [body_pos, any_headers?]; nil is Go's `return nil` when input ends
        # mid-header.
        # :reek:TooManyStatements -- a faithful port of the header-parsing loop.
        def self.skip_headers(data, pos)
          any = false
          loop do
            return nil if pos >= data.length

            line, after = get_line(data, pos)
            return [pos, any] unless line.include?(":")

            any = true
            pos = after
          end
        end
        private_class_method :skip_headers

        # Std-base64-decode the block body `data[from...upto]`, or nil when it is not valid base64
        # (Go's pem.Decode skips such a block). Go's removeSpacesAndTabs strips " \t" and the base64
        # decoder ignores "\r\n"; strict_decode64 ignores nothing, so all four are removed first to
        # reproduce Go's accept/reject set exactly. The region is first probed for a non-base64 byte
        # with a single forward index scan (no slice) — if one falls inside the region the decode is
        # doomed, so we return before materializing the (possibly huge) body. That bounds the work to
        # the offset of the first invalid byte, keeping a failed BEGIN's retry linear and mirroring
        # Go's decoder erroring at the first invalid byte.
        def self.decode_region(data, from, upto)
          bad = data.index(NON_BASE64_BYTE, from)
          return nil if bad && bad < upto

          Base64.strict_decode64(data[from...upto].to_s.delete(BASE64_SKIP))
        rescue ArgumentError
          nil
        end
        private_class_method :decode_region

        # Byte-oriented encoding guard (matching uri.rb / net.rb): reject invalid-encoding and
        # ASCII-incompatible (UTF-16/32) strings — which would make each_line/Regexp/start_with? raise
        # — but admit ASCII-8BIT, since base64.decode yields ASCII-8BIT PEM bytes that the byte-level
        # scan handles cleanly. The stricter ascii_only?/UTF-8 guard would over-reject those (diverging
        # from OPA), so this is the correct level for byte-oriented PEM scanning. See the encoding-guard
        # memory note's byte-oriented vs char-oriented distinction.
        def self.scannable?(string)
          string.encoding.ascii_compatible? && string.valid_encoding?
        end
        private_class_method :scannable?

        # Parse a block's DER bytes as a private key, or nil if OpenSSL rejects it (never raise). Go's
        # x509 parsers read one leading ASN.1 SEQUENCE via asn1.Unmarshal and treat the remainder as
        # `rest`; PKCS#8 and SEC1 ignore that trailing data while PKCS#1 ("RSA PRIVATE KEY") rejects
        # it. This bounds the parse to that leading element and applies the per-type trailing rule, so
        # the result matches OPA (incl. valid-key-plus-trailing) — and OpenSSL never sees more than
        # MAX_KEY_DER_BYTES, the DoS guard: OpenSSL::PKey.read trial-parses every format and would
        # burn seconds on a multi-MB garbage DER where Go's typed parsers fast-fail. A public key in a
        # PRIVATE KEY block parses but lacks private material, so it is dropped (matching OPA).
        # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
        # :reek:TooManyStatements -- the bound + per-type trailing rule + parse read clearest inline.
        def self.read_key(type, der)
          size = der.bytesize
          total = leading_element_length(der) || (return nil)
          return nil if total > MAX_KEY_DER_BYTES || total > size
          return nil if total < size && type == "RSA PRIVATE KEY"

          element = der.byteslice(0, total).to_s
          return nil unless format_matches?(type, element)

          key = OpenSSL::PKey.read(element, "")
          private_material?(key) ? key : nil
        rescue OpenSSL::OpenSSLError, ArgumentError
          nil
        end
        # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
        private_class_method :read_key

        # Whether the DER's format matches the one Go's parser for this block type accepts (see
        # BLOCK_FORMAT_ELEMENT) — gating out a key re-encoded under a mislabelled block header. A
        # structurally-invalid DER (decode raises) is simply "no match"; SystemStackError is rescued
        # because OpenSSL::ASN1.decode recurses through nested constructed types with no depth limit
        # (openssl < master), so a deeply-nested DER within the size cap could otherwise overflow the
        # stack on a small-stack thread and escape the registry's narrow rescue.
        def self.format_matches?(type, der)
          OpenSSL::ASN1.decode(der).value[1].is_a?(BLOCK_FORMAT_ELEMENT.fetch(type))
        rescue OpenSSL::ASN1::ASN1Error, TypeError, NoMethodError, SystemStackError
          false
        end
        private_class_method :format_matches?

        # The total byte length (header + content) of the leading DER SEQUENCE, or nil if `der` does
        # not begin with a definite-length SEQUENCE (which Go's asn1.Unmarshal would reject). Only the
        # length prefix is read — content is never scanned — so a huge claimed length is rejected in
        # O(1) by the caller's cap rather than handed to OpenSSL.
        # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
        # :reek:TooManyStatements -- the short-form/long-form DER length parse reads clearest inline.
        def self.leading_element_length(der)
          size = der.bytesize
          return nil if size < 2 || der.getbyte(0) != 0x30

          first = der.getbyte(1).to_i
          return first + 2 if first < 0x80

          count = first & 0x7f
          return nil if count.zero? || count > 4 || size < count + 2

          length_bytes = der.byteslice(2, count).to_s.bytes
          return nil if length_bytes.first&.zero? # DER: no superfluous leading zero in the length

          length = length_bytes.reduce(0) { |acc, byte| (acc << 8) | byte }
          return nil if length < 0x80 # DER: long form must not encode a value the short form could

          length + count + 2
        end
        # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
        private_class_method :leading_element_length

        # Whether the parsed key carries a private component. RSA/EC/DSA expose #private?; the raw
        # OKP types (Ed25519/X25519) do not, and raise PKeyError from raw_private_key when public-only.
        # :reek:ManualDispatch -- the OpenSSL key classes genuinely differ in whether #private? exists.
        def self.private_material?(key)
          return key.private? if key.respond_to?(:private?)

          key.raw_private_key
          true
        rescue OpenSSL::PKey::PKeyError
          false
        end
        private_class_method :private_material?

        # Whether Go's x509 would parse this key type — RSA, Ed25519, X25519, or EC on one of Go's
        # four crypto/elliptic curves. DSA, Ed448, X448 and other EC curves are unsupported. An EC
        # key must also carry a public point: OpenSSL 3.x derives it from the scalar, but an older
        # build might not, and the renderers need it — drop such a key rather than risk a nil deref.
        # :reek:NilCheck -- the public-point presence check guards the EC renderers against a nil point.
        def self.go_supported?(key)
          case key.oid
          when "rsaEncryption", "ED25519", "X25519" then true
          when "id-ecPublicKey" then EC_STRUCT_CURVES.include?(key.group.curve_name) && !key.public_key.nil?
          else false
          end
        end
        private_class_method :go_supported?

        # Render a supported key as a JWK hash, or nil when the JWK encoding does not cover it (a
        # P-224 EC key — OPA's jwk.Import rejects it even though the struct output handles it).
        def self.jwk_for(key)
          case key.oid
          when "id-ecPublicKey" then EC_CURVE_NAMES.key?(key.group.curve_name) ? ec_jwk(key) : nil
          when "ED25519" then okp_jwk(key, "Ed25519")
          when "X25519" then okp_jwk(key, "X25519")
          else rsa_jwk(key)
          end
        end
        private_class_method :jwk_for

        def self.rsa_jwk(key)
          {
            "kty" => "RSA",
            "n" => b64url_bn(key.n), "e" => b64url_bn(key.e), "d" => b64url_bn(key.d),
            "p" => b64url_bn(key.p), "q" => b64url_bn(key.q),
            "dp" => b64url_bn(key.dmp1), "dq" => b64url_bn(key.dmq1), "qi" => b64url_bn(key.iqmp)
          }
        end
        private_class_method :rsa_jwk

        # EC JWK: coordinates and the private scalar are fixed curve-width (left-zero-padded), per
        # RFC 7518 — unlike RSA's minimal integers.
        # :reek:UncommunicativeVariableName -- x/y are the standard names for EC point coordinates.
        def self.ec_jwk(key)
          group = key.group
          x, y = point_coordinates(key)
          {
            "kty" => "EC", "crv" => EC_CURVE_NAMES.fetch(group.curve_name),
            "x" => b64url(x), "y" => b64url(y),
            "d" => b64url(left_pad(key.private_key.to_s(2), coordinate_width(group)))
          }
        end
        private_class_method :ec_jwk

        # OKP JWK for the Edwards/Montgomery raw-key types (Ed25519, X25519).
        def self.okp_jwk(key, curve)
          { "kty" => "OKP", "crv" => curve, "x" => b64url(key.raw_public_key), "d" => b64url(key.raw_private_key) }
        end
        private_class_method :okp_jwk

        # Render a supported key as its Go encoding/json shape by type. X25519 is Go's ecdh.PrivateKey,
        # which has no exported fields and marshals to {}.
        def self.go_struct_for(key)
          case key.oid
          when "id-ecPublicKey" then ec_struct(key)
          when "ED25519" then Base64.strict_encode64(key.raw_private_key + key.raw_public_key)
          when "X25519" then {}
          else rsa_struct(key)
          end
        end
        private_class_method :go_struct_for

        # Go's rsa.PrivateKey: big.Int modulus/exponents as decimals, the CRT precomputed values, and
        # the prime factors. CRTValues is the (empty, for 2-prime keys) extra-prime chain.
        def self.rsa_struct(key)
          crt_values = [] # : Array[untyped]
          {
            "N" => key.n.to_i, "E" => key.e.to_i, "D" => key.d.to_i,
            "Primes" => [key.p.to_i, key.q.to_i],
            "Precomputed" => {
              "Dp" => key.dmp1.to_i, "Dq" => key.dmq1.to_i, "Qinv" => key.iqmp.to_i, "CRTValues" => crt_values
            }
          }
        end
        private_class_method :rsa_struct

        # Go's ecdsa.PrivateKey: the curve (marshalled as {} — no exported fields) plus the scalar and
        # public-point coordinates as big.Ints.
        # :reek:UncommunicativeVariableName -- x/y are the standard names for EC point coordinates.
        def self.ec_struct(key)
          x, y = point_coordinates(key)
          { "Curve" => {}, "D" => key.private_key.to_i, "X" => bytes_to_int(x), "Y" => bytes_to_int(y) }
        end
        private_class_method :ec_struct

        # The big-endian X and Y of the public point (each `coordinate_width` bytes), from the
        # uncompressed "0x04 || X || Y" encoding.
        def self.point_coordinates(key)
          width = coordinate_width(key.group)
          encoded = key.public_key.to_bn(:uncompressed).to_s(2)
          [encoded[1, width].to_s, encoded[1 + width, width].to_s]
        end
        private_class_method :point_coordinates

        def self.coordinate_width(group)
          (group.degree + 7) / 8
        end
        private_class_method :coordinate_width

        def self.bytes_to_int(bytes)
          OpenSSL::BN.new(bytes, 2).to_i
        end
        private_class_method :bytes_to_int

        # base64url (no padding) of an OpenSSL::BN's minimal big-endian bytes (matches Go big.Int.Bytes).
        def self.b64url_bn(big_number)
          b64url(big_number.to_s(2))
        end
        private_class_method :b64url_bn

        def self.b64url(bytes)
          Base64.urlsafe_encode64(bytes, padding: false)
        end
        private_class_method :b64url

        def self.left_pad(bytes, width)
          bytes.rjust(width, "\x00".b)
        end
        private_class_method :left_pad
      end
      # rubocop:enable Metrics/ModuleLength
    end
  end
end
