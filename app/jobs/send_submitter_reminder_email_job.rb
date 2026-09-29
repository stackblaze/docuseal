# frozen_string_literal: true

class SendSubmitterReminderEmailJob
  include Sidekiq::Job

  def perform(params = {})
    submitter = Submitter.find_by(id: params['submitter_id'])

    return unless submitter
    return if submitter.email.blank?
    return if submitter.completed_at?
    return if submitter.declined_at?
    return if submitter.sent_at.blank?
    return if submitter.submission.archived_at?
    return if submitter.submission.expired?
    return if submitter.template&.archived_at?

    key = params['duration_key']
    config = AccountConfigs.find_for_account(submitter.account, AccountConfig::SUBMITTER_REMINDERS)&.value
    return unless config.is_a?(Hash)

    interval = AccountConfigs::REMINDER_INTERVALS[config[key]]
    return unless interval
    return if Time.current < submitter.sent_at + interval - 2.minutes

    sent = Array(submitter.preferences['reminders_sent'])
    return if sent.include?(key)

    unless Accounts.can_send_invitation_emails?(submitter.account)
      Rollbar.warning("Skip reminder email: #{submitter.account.id}") if defined?(Rollbar)

      return
    end

    mail = SubmitterMailer.reminder_email(submitter)

    Submitters::ValidateSending.call(submitter, mail)

    mail.deliver_now!

    SubmissionEvent.create!(submitter:, event_type: 'send_reminder_email')

    submitter.update!(preferences: submitter.preferences.merge('reminders_sent' => sent + [key]))
  end
end
