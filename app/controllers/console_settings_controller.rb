# frozen_string_literal: true

class ConsoleSettingsController < ApplicationController
  def index
    authorize! :manage, EncryptedConfig

    options = Docuseal.default_url_options
    port = options[:port]
    @app_url = "#{options[:protocol]}://#{options[:host]}#{":#{port}" if port && [80, 443].exclude?(port)}"
    @version = Docuseal.version.presence || 'development'
  end
end
