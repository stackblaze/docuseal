# frozen_string_literal: true

class SamlController < ApplicationController
  skip_before_action :authenticate_user!
  skip_before_action :maybe_redirect_to_setup
  skip_authorization_check
  skip_forgery_protection only: :consume

  def metadata
    render xml: OneLogin::RubySaml::Metadata.new.generate(Saml.settings_for(saml_account)),
           content_type: 'application/samlmetadata+xml'
  end

  def consume
    request.get? ? start_login : finish_login
  end

  private

  def start_login
    account = Saml.account_with_config
    unless Saml.configured?(account)
      redirect_to new_user_session_path, alert: 'SAML SSO is not configured.'
      return
    end

    redirect_to OneLogin::RubySaml::Authrequest.new.create(Saml.settings_for(account)), allow_other_host: true
  end

  def finish_login
    account = Saml.account_with_config
    unless Saml.configured?(account)
      redirect_to new_user_session_path, alert: 'SAML SSO is not configured.'
      return
    end

    response = OneLogin::RubySaml::Response.new(params[:SAMLResponse], settings: Saml.settings_for(account))
    unless response.is_valid?
      redirect_to new_user_session_path, alert: 'SAML sign-in failed. Check the identity provider settings.'
      return
    end

    user = User.active.find_by(email: response.nameid.to_s.downcase.strip)
    unless user&.active_for_authentication? && user_allowed?(user, account)
      redirect_to new_user_session_path, alert: 'No active user matches that SSO email.'
      return
    end

    sign_in(user)
    redirect_to safe_return_path
  end

  def saml_account
    current_account || Saml.account_with_config || Account.active.order(:id).first
  end

  def user_allowed?(user, account)
    return true if user.account_id == account.id

    user.account.linked_account_account&.account_id == account.id
  end

  def safe_return_path
    path = params[:RelayState].to_s
    return root_path unless path.start_with?('/') && !path.start_with?('//')

    path
  end
end
