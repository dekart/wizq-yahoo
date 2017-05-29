module WizqYahoo
  class User
    class InvalidSignature < StandardError; end

    class << self
      def from_wizq_yahoo_request(config, request)
        new( parse_wizq_yahoo_signed_params(config, request) )
      end

      def parse_wizq_yahoo_signed_params(config, request)
        if request.params[:signed_params]
          # parse params passed by the game
          parse_signed_params(config, request.params[:signed_params]) 

        else
          # take params passed by the wizQ gateway
          if config.request_validator.validate_signed_request(request)
            request.params.slice(*Rails::Controller::WIZQ_YAHOO_PARAM_NAMES).merge(
              access_token: SecureRandom.urlsafe_base64
            )
          else
            raise InvalidSignature.new('Invalid request signature')
          end
        end
      end

      def parse_signed_params(config, input)
        encoded_sig, encoded_data = input.split('.', 2)
        signature = base64_url_decode(encoded_sig).unpack("H*").first

        MultiJson.decode(base64_url_decode(encoded_data)).tap do |params|
          unless signature == OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, config.consumer_secret, encoded_data)
            raise InvalidSignature.new('Invalid request signature')
          end
        end
      end

      # Facebook approach to encrypting params
      def base64_url_decode(str)
        str += '=' * (4 - str.length.modulo(4))
        Base64.decode64(str.tr('-_', '+/'))
      end
    end

    def initialize(options = {})
      @options = options
    end

    def access_token
      @options['access_token']
    end

    def authenticated?
      access_token && !access_token.empty?
    end

    def uid
      @options['opensocial_viewer_id']
    end
  end
end
