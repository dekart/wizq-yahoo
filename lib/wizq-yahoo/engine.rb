module WizqYahoo
  class Engine < ::Rails::Engine
    initializer "wizq-yahoo.middleware" do |app|
      app.middleware.insert_before(Rack::Head, WizqYahoo::Middleware)
    end

    initializer "wizq-yahoo.controller_extension" do
      ActiveSupport.on_load :action_controller do
        ActionController::Base.send(:include, WizqYahoo::Rails::Controller)
      end
    end
  end
end
