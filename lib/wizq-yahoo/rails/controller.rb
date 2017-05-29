require 'wizq-yahoo/rails/controller/redirects'

module WizqYahoo
  module Rails

    # Rails application controller extension
    module Controller
      def self.included(base)
        base.class_eval do
          include WizqYahoo::Rails::Controller::Redirects

          helper_method :wizq_yahoo, :current_wizq_yahoo_user, :wizq_yahoo_params, :params_without_wizq_yahoo_data, :wizq_yahoo_canvas?
        end
      end

      protected

        WIZQ_YAHOO_PARAM_NAMES = %w{oauth_body_hash opensocial_owner_id opensocial_viewer_id opensocial_app_id opensocial_app_url
         oauth_consumer_key xoauth_public_key oauth_version oauth_timestamp oauth_signature_method oauth_nonce oauth_signature}

        RAILS_PARAMS = %w{controller action format}

        # Accessor to current application config. Override it in your controller
        # if you need multi-application support or per-request configuration selection.
        def wizq_yahoo
          WizqYahoo::Config.default
        end

        # Accessor to current Yahoo Mobage user. Returns instance of WizqYahoo::User
        def current_wizq_yahoo_user
          @current_wizq_yahoo_user ||= fetch_current_wizq_yahoo_user
        end

        # params coming directly from WizqYahoo
        def wizq_yahoo_params
          params.slice(*WIZQ_YAHOO_PARAM_NAMES)
        end

        # A hash of params passed to this action, excluding secure information passed by wizQ
        def params_without_wizq_yahoo_data
          params.except(*WIZQ_YAHOO_PARAM_NAMES)
        end

        # Did the request come from canvas app
        def wizq_yahoo_canvas?
          params['wizq_player_id'].present? || wizq_yahoo_params['oauth_consumer_key'].present? || request.env['HTTP_SIGNED_PARAMS'].present?
        end

        def wizq_yahoo_signed_params
          request.env['HTTP_SIGNED_PARAMS'] || build_signed_params(wizq_yahoo_params)
        end

        def validate_wizq_yahoo_payment_request
          wizq_yahoo.payment_validator.check_signature(request)
        end

      private

        def fetch_current_wizq_yahoo_user
          WizqYahoo::User.from_wizq_yahoo_request(wizq_yahoo, request)
        end

        def build_signed_params(data)
          string = base64_url_encode( MultiJson.encode(data) )
          signature = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, wizq_yahoo.consumer_secret, string)

          [
            base64_url_encode( [signature].pack("H*")),
            string
          ].join('.')
        end

        # Facebook approach to encrypting params
        def base64_url_encode(str)
          Base64.strict_encode64(str).tr('+/', '-_').tr('=', '')
        end
    end
  end
end
