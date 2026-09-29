# frozen_string_literal: true

class AccountLogosController < ApplicationController
  ALLOWED_TYPES = %w[image/png image/jpeg image/webp image/gif image/svg+xml].freeze

  def create
    authorize! :update, current_account

    file = params[:logo]
    if file.blank? || ALLOWED_TYPES.exclude?(file.content_type) || file.size > 2.megabytes
      redirect_back fallback_location: settings_personalization_path, alert: I18n.t('unable_to_save')
      return
    end

    current_account.logo.attach(file)
    redirect_back fallback_location: settings_personalization_path, notice: I18n.t('settings_have_been_saved')
  end

  def destroy
    authorize! :update, current_account

    current_account.logo.purge
    redirect_back fallback_location: settings_personalization_path, notice: I18n.t('settings_have_been_saved')
  end
end
