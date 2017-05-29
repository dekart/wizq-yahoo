require 'addressable'

module WizqYahoo
    class OAuthConsumer
      attr_accessor :key, :secret

      def initialize(key, secret, callback_url = nil)
        @key = key
        @secret = secret
        @callback_url = callback_url
      end
    end

    class OAuthToken
      attr_accessor :key, :secret

      def initialize(key, secret)
        @key = key
        @secret = secret
      end
    end

    # abstract
    class OAuthSignatureMethod
      # returns the name of the Signature Method (ie HMAC-SHA1)
      def get_name
      end

      # builds up the signature
      def build_signature(request, consumer, token)
      end

      # verifies that a given signature is correct
      def check_signature(request, consumer, token, signature)
        build_signature(request, consumer, token) == signature
      end

      private

      def encode(value)
        case value
        when Array
          value.map{ |v| encode(v) }
        when Hash
          ''
        when String, Numeric
          ::Addressable::URI.encode_component(
            value,
            ::Addressable::URI::CharacterClasses::UNRESERVED
          )
        end
      end

      def get_signature_base_string(request)
        parts = [
          request.method.to_s.upcase,
          normalize_uri(request),
          normalize_params(request.params)
        ]

        parts.map{ |value| encode(value) }.join('&')
      end

      def normalize_uri(request)
        [request.protocol, request.host, request.path].join

        parsed_uri = ::Addressable::URI.parse(request.original_url)
        uri = ::Addressable::URI.new(
          :scheme => parsed_uri.normalized_scheme,
          :authority => parsed_uri.normalized_authority,
          :path => parsed_uri.path,
          :fragment => parsed_uri.fragment
        )

        uri.to_s
      end

      def normalize_params(params)
        if !params.kind_of?(Enumerable)
          raise TypeError, "Expected Enumerable, got #{parameters.class}"
        end
        
        parameter_list = params.except('controller', 'action', 'format', 'oauth_signature').map do |k, v|
          key = encode(k)
          value = encode(v)
          
          if key.blank? or value.blank?
            nil
          else
            "#{ key }=#{ value }"
          end
        end

        parameter_list.compact.sort.join("&")
      end
    end

    #
    # implementations of OAuthSignatureMethod
    ############################################

    # The PLAINTEXT method does not provide any security protection and SHOULD only be used over a secure channel such as HTTPS.
    # It does not use the Signature Base String.
    class OAuthSignatureMethod_PLAINTEXT < OAuthSignatureMethod
      def get_name
        'PLAINTEXT'
      end

      def build_signature(request, consumer, token)
        [consumer.secret, token ? token.secret : ""].map{ |value| encode(value) }.join('&')
      end
    end

    # The HMAC-SHA1 signature method uses the HMAC-SHA1 signature algorithm as defined in [RFC2104] 
    # where the Signature Base String is the text and the key is the concatenated values (each first encoded per Parameter Encoding)
    # of the Consumer Secret and Token Secret, separated by an '&' character (ASCII code 38) even if empty.
    class OAuthSignatureMethod_HMAC_SHA1 < OAuthSignatureMethod
      def get_name
        'HMAC-SHA1'
      end

      def build_signature(request, consumer, token)
        base_string = get_signature_base_string(request)

        key = [consumer.secret, token ? token.secret : ""].map{ |value| encode(value) }.join('&')

        Base64.encode64( OpenSSL::HMAC.digest('sha1', key, base_string) ).strip
      end
    end

    # The RSA-SHA1 signature method uses the RSASSA-PKCS1-v1_5 signature algorithm as defined in [RFC3447] section 8.2 (more simply known as PKCS#1),
    # using SHA-1 as the hash function for EMSA-PKCS1-v1_5. It is assumed that the Consumer has provided its RSA public key in a verified way to the Service Provider,
    # in a manner which is beyond the scope of this specification.
    class OAuthSignatureMethod_RSA_SHA1 < OAuthSignatureMethod
      def get_name
        'RSA-SHA1'
      end

      def fetch_public_cert(request)
      end

      def fetch_private_cert(request)
      end

      def check_signature(request, consumer, token, signature)
        signature = Base64.decode64(signature)

        base_string = get_signature_base_string(request)

        # Fetch the private key cert based on the request
        certificate = OpenSSL::X509::Certificate.new( fetch_public_cert(request) )

        # Check the computed signature against the one passed in the query
        certificate.public_key.verify(OpenSSL::Digest::SHA1.new, signature, base_string).tap do
          OpenSSL.errors.clear # clear OpenSSL error
        end
      end
    end
end
