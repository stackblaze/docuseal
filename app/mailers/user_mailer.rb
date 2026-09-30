# frozen_string_literal: true

class UserMailer < ApplicationMailer
  def invitation_email(user, invited_by: nil)
    @current_account = invited_by&.account || user.account
    @user = user
    @token = @user.send(:set_reset_password_token)

    assign_message_metadata('user_invitation', @user)

    I18n.with_locale(@current_account.locale) do
      mail(to: @user.friendly_name,
           subject: I18n.t('you_are_invited_to_product_name', product_name: Docuseal.product_name))
    end
  end

  def magic_link_email(user, token)
    @user = user
    @current_account = user.account
    @url = magic_link_url(token:)

    assign_message_metadata('user_magic_link', @user)

    I18n.with_locale(@current_account.locale) do
      mail(to: @user.friendly_name, subject: "Your #{Docuseal.product_name} sign-in link")
    end
  end
end
