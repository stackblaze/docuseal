# frozen_string_literal: true

class SendSubmitterInvitationEmailJob
  include Sidekiq::Job

  def perform(params = {})
    submitter = Submitter.find(params['submitter_id'])

    return if submitter.completed_at?
    return if submitter.declined_at?
    return if submitter.submission.archived_at?
    return if submitter.submission.expired?
    return if submitter.template&.archived_at?
    return if submitter.submission.source == 'invite' && !Accounts.can_send_emails?(submitter.account, on_events: true)

    unless Accounts.can_send_invitation_emails?(submitter.account)
      Rollbar.warning("Skip email: #{submitter.account.id}") if defined?(Rollbar)

      return
    end

    mail =
      if submitter.viewer?
        SubmitterMailer.invitation_view_email(submitter)
      else
        SubmitterMailer.invitation_email(submitter)
      end

    Submitters::ValidateSending.call(submitter, mail)

    mail.deliver_now!

    SubmissionEvent.create!(submitter:, event_type: 'send_email')

    submitter.sent_at ||= Time.current
    submitter.save!

    schedule_reminders(submitter)
  end

  def schedule_reminders(submitter)
    config = AccountConfigs.find_for_account(submitter.account, AccountConfig::SUBMITTER_REMINDERS)&.value
    return unless config.is_a?(Hash)

    %w[first_duration second_duration third_duration].each do |key|
      interval = AccountConfigs::REMINDER_INTERVALS[config[key]]
      next unless interval

      SendSubmitterReminderEmailJob.perform_in(interval, 'submitter_id' => submitter.id, 'duration_key' => key)
    end
  end
end
