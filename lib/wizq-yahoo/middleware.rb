# This rack middleware converts POST requests from Wizq to GET requests.
# It's necessary to make RESTful routes work as expected without any changes
# in the application.
module WizqYahoo
  class Middleware
    def initialize(app, options = {})
      @app = app
    end

    def call(env)
      request = ::Rack::Request.new(env)

      # only for requests sent from game
      if request.POST['signed_params']
        if request.post? && request.params['_method'].blank?
          env['REQUEST_METHOD'] = 'GET'
        end

        # Put signed_request parameter to the same place where HTTP header X-Signed-Request come.
        # This let us work both with params and HTTP headers in the same way. Very useful for AJAX.
        env['HTTP_SIGNED_PARAMS'] ||= request.POST['signed_params']

        # parameters passed through the WizQ gateway should be url-encoded, non-scalar parameters are also JSON-encoded
        request.params.each do |name, value|
          next if name =~ /^oauth_/

          result = CGI.unescape( value )

          begin
            result = JSON.parse(result)
          rescue JSON::ParserError => e
          end

          request.update_param(name, result)
        end
      end

      @app.call(env)
    end
  end
end
