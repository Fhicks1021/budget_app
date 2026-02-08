use anyhow::{Context, Result};
use lettre::message::Mailbox;
use lettre::transport::smtp::SmtpTransport;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, Transport};

pub struct SmtpEmailer {
    mailer: SmtpTransport,
    from: Mailbox,
}

impl SmtpEmailer {
    pub fn new(host: &str, username: &str, password: &str, from: &str) -> Result<Self> {
        let creds = Credentials::new(username.to_string(), password.to_string());

        let mailer = SmtpTransport::starttls_relay(host)
            .context("Failed to build SMTP relay")?
            .credentials(creds)
            .build();

        let from: Mailbox = from
            .parse()
            .context("MAIL_FROM is not a valid email/mailbox")?;

        Ok(Self { mailer, from })
    }

    pub fn send_password_reset(&self, to: &str, reset_link: &str) -> Result<()> {
        let to: Mailbox = to.parse().context("Recipient email is invalid")?;

        let msg = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject("Reset your password")
            .body(format!(
                "Someone requested a password reset.\n\nReset link:\n{}\n\nIf this wasn’t you, ignore this email.",
                reset_link
            ))?;

        self.mailer.send(&msg).context("SMTP send failed")?;
        Ok(())
    }
}
