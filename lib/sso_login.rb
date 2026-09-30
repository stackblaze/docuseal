# frozen_string_literal: true

# Rules shared by SAML, OIDC, and magic-link sign-in.
module SsoLogin
  module_function

  def find_user(email, account)
    user = User.active.find_by(email: email.to_s.downcase.strip)
    return unless user&.active_for_authentication?
    return user if account.blank? || user_in_account?(user, account)

    nil
  end

  def user_in_account?(user, account)
    user.account_id == account.id || user.account.linked_account_account&.account_id == account.id
  end

  # Password and magic-link sign-in are disabled when an account forces SSO and has SAML or OIDC configured.
  def forced?
    AccountConfig.where(key: AccountConfig::FORCE_SSO_AUTH_KEY).any? do |config|
      config.value == true && (Saml.configured?(config.account) || OidcSso.enabled_providers(config.account).any?)
    end
  end
end
