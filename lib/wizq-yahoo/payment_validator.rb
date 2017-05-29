module WizqYahoo
  class PaymentValidator
    attr_accessor :key, :secret

    def initialize(key, secret)
      @key = key
      @secret = secret
    end

    def check_signature(request)
      consumer = OAuthConsumer.new(key, secret, nil)
      token = OAuthToken.new(request.params['oauth_token'], request.params['oauth_token_secret'])
      signature = request.params['oauth_signature']

      signature_method = OAuthSignatureMethod_HMAC_SHA1.new
      signature_method.check_signature(request, consumer, token, signature)
    end
  end
end
