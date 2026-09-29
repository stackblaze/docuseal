# frozen_string_literal: true

class SsoSettingsController < ApplicationController
  before_action :load_encrypted_config
  authorize_resource :encrypted_config, only: :index
  authorize_resource :encrypted_config, parent: false, only: :create

  def index
    @force_sso = sso_forced?
  end

  def create
    value = saml_value
    @encrypted_config.value = value
    @force_sso = params[:force_sso] == '1'

    if value['sso_url'].blank? && value['certificate'].blank?
      @encrypted_config.destroy! if @encrypted_config.persisted?
      update_force_sso(false)
      redirect_to settings_sso_index_path, notice: I18n.t('sso_settings_have_been_updated')
      return
    end

    unless Saml.valid_sso_url?(value['sso_url']) && Saml.valid_certificate?(value['certificate'])
      flash.now[:alert] = 'Enter a valid SSO Service URL and an X.509 certificate.'
      render :index, status: :unprocessable_content
      return
    end

    @encrypted_config.save!
    update_force_sso(@force_sso)
    redirect_to settings_sso_index_path, notice: I18n.t('sso_settings_have_been_updated')
  end

  private

  def load_encrypted_config
    @encrypted_config =
      EncryptedConfig.find_or_initialize_by(account: current_account, key: EncryptedConfig::SAML_CONFIGS_KEY)
  end

  def saml_value
    submitted = params.require(:encrypted_config).permit(value: %i[sso_url certificate]).fetch(:value, {})
    current = @encrypted_config.value.is_a?(Hash) ? @encrypted_config.value : {}
    certificate = Saml.normalize_certificate(submitted[:certificate])
    certificate = current['certificate'].to_s if certificate.blank?

    {
      'sso_url' => submitted[:sso_url].to_s.strip,
      'certificate' => certificate
    }
  end

  def sso_forced?
    AccountConfig.find_by(account: current_account, key: AccountConfig::FORCE_SSO_AUTH_KEY)&.value == true
  end

  def update_force_sso(enabled)
    config = AccountConfig.find_or_initialize_by(account: current_account, key: AccountConfig::FORCE_SSO_AUTH_KEY)
    if enabled
      config.update!(value: true)
    elsif config.persisted?
      config.destroy!
    end
  end
end
