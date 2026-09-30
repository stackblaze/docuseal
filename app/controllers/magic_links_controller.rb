# frozen_string_literal: true

class MagicLinksController < ApplicationController
  skip_before_action :authenticate_user!
  skip_before_action :maybe_redirect_to_setup
  skip_authorization_check

  before_action :ensure_available

  rate_limit to: 5, within: 10.minutes, only: :create,
             by: -> { params[:email].to_s.downcase.presence || request.remote_ip },
             with: -> { redirect_to new_magic_link_path, alert: I18n.t(:rate_limit_exceeded) }

  # Mail scanners follow GET links, so the link opens a confirmation page and sign-in happens on POST.
  def show
    @token = params[:token].to_s
    @user = MagicLink.find_user(@token)

    redirect_to new_user_session_path, alert: invalid_message unless @user
  end

  def new; end

  # Always answers the same way so the form cannot be used to discover accounts.
  def create
    user = SsoLogin.find_user(params[:email], nil)

    UserMailer.magic_link_email(user, MagicLink.generate(user)).deliver_later if user && MagicLink.enabled_for?(user)

    redirect_to new_user_session_path,
                notice: 'If an account exists for that email, a sign-in link is on its way. It expires in 15 minutes.'
  end

  def consume
    user = MagicLink.find_user(params[:token])
    return redirect_to new_user_session_path, alert: invalid_message unless user

    if user.otp_required_for_login && !user.validate_and_consume_otp!(params[:otp_attempt].to_s)
      @token = params[:token].to_s
      @user = user
      flash.now[:alert] = I18n.t('devise.failure.invalid_two_factor', default: 'Invalid two-factor code.')
      return render :show, status: :unprocessable_content
    end

    sign_in(user)
    redirect_to root_path
  end

  private

  def ensure_available
    return if MagicLink.enabled? && !SsoLogin.forced?

    redirect_to new_user_session_path, alert: 'Email sign-in links are turned off.'
  end

  def invalid_message
    'This sign-in link is invalid, expired, or already used. Request a new one.'
  end
end
