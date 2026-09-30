# frozen_string_literal: true

class OidcController < ApplicationController
  SESSION_KEY = 'oidc_login'

  skip_before_action :authenticate_user!
  skip_before_action :maybe_redirect_to_setup
  skip_authorization_check

  before_action :load_provider

  def show
    state = SecureRandom.urlsafe_base64(32)
    nonce = SecureRandom.urlsafe_base64(32)
    code_verifier = SecureRandom.urlsafe_base64(48)

    session[SESSION_KEY] = {
      'provider' => @provider, 'state' => state, 'nonce' => nonce,
      'code_verifier' => code_verifier, 'account_id' => @account.id, 'started_at' => Time.current.to_i
    }

    redirect_to OidcSso.authorize_url(@account, @provider, redirect_uri:, state:, nonce:, code_verifier:),
                allow_other_host: true
  rescue OidcSso::Error, SocketError, Timeout::Error, Errno::ECONNREFUSED => e
    Rails.logger.error("OIDC #{@provider} start failed: #{e.message}")
    redirect_to new_user_session_path, alert: "#{OidcSso.display_name(@provider)} sign-in is unavailable right now."
  end

  def callback
    pending = session.delete(SESSION_KEY)

    if params[:error].present?
      return redirect_to new_user_session_path, alert: "#{OidcSso.display_name(@provider)} sign-in was cancelled."
    end

    unless valid_pending?(pending)
      return redirect_to new_user_session_path, alert: 'Your sign-in session expired. Try again.'
    end

    email = OidcSso.verified_email(@account, @provider,
                                   code: params[:code].to_s, redirect_uri:,
                                   nonce: pending['nonce'], code_verifier: pending['code_verifier'])
    user = SsoLogin.find_user(email, @account)

    unless user
      Rails.logger.warn("OIDC #{@provider} sign-in for #{email}: no matching active user")
      return redirect_to new_user_session_path, alert: 'No active user matches that email.'
    end

    sign_in(user)
    redirect_to root_path
  rescue OidcSso::Error, SocketError, Timeout::Error, Errno::ECONNREFUSED => e
    Rails.logger.error("OIDC #{@provider} callback failed: #{e.message}")
    redirect_to new_user_session_path, alert: "#{OidcSso.display_name(@provider)} sign-in failed."
  end

  private

  def load_provider
    @provider = params[:provider].to_s
    @account = OidcSso.account_with_config

    return if OidcSso::PROVIDERS.key?(@provider) && OidcSso.configured?(@account, @provider)

    redirect_to new_user_session_path, alert: 'That sign-in method is not configured.'
  end

  def valid_pending?(pending)
    pending.is_a?(Hash) &&
      pending['provider'] == @provider &&
      pending['account_id'] == @account.id &&
      pending['started_at'].to_i > 10.minutes.ago.to_i &&
      params[:state].present? &&
      ActiveSupport::SecurityUtils.secure_compare(params[:state].to_s, pending['state'].to_s)
  end

  def redirect_uri
    oidc_callback_url(@provider, **Docuseal.default_url_options)
  end
end
