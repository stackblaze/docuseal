# frozen_string_literal: true

# Single-use, short-lived sign-in links sent by email.
#
# The token signs the user's current sign-in timestamp and a slice of the password hash.
# Devise's trackable module updates current_sign_in_at on every sign-in, so a link stops
# working once it (or any other method) has been used to sign in, and a password change voids it too.
module MagicLink
  TTL = 15.minutes
  PURPOSE = :magic_link_login

  module_function

  def enabled?
    AccountConfig.where(key: AccountConfig::MAGIC_LINK_LOGIN_KEY).any? { |config| config.value == true }
  end

  def enabled_for?(user)
    accounts = [user.account, user.account.linked_account_account&.account].compact
    AccountConfig.where(account: accounts, key: AccountConfig::MAGIC_LINK_LOGIN_KEY).any? { |config| config.value == true }
  end

  def generate(user)
    verifier.generate(fingerprint(user), expires_in: TTL, purpose: PURPOSE)
  end

  def find_user(token)
    data = verifier.verified(token.to_s, purpose: PURPOSE)
    return unless data.is_a?(Array)

    user = User.active.find_by(id: data.first)
    return unless user&.active_for_authentication? && enabled_for?(user)
    return unless ActiveSupport::SecurityUtils.secure_compare(data.to_json, fingerprint(user).to_json)

    user
  rescue ActiveSupport::MessageVerifier::InvalidSignature, ArgumentError
    nil
  end

  def fingerprint(user)
    [user.id, user.current_sign_in_at&.to_f.to_s, user.encrypted_password.to_s.last(12)]
  end

  def verifier
    Rails.application.message_verifier(PURPOSE)
  end
end
