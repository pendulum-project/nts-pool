use std::str::FromStr;

use anyhow::Context;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::error::AppError;

pub type MailTransport = AsyncSmtpTransport<Tokio1Executor>;

#[derive(Debug, Clone)]
pub struct Mailer {
    transport: MailTransport,
    from_address: lettre::message::Mailbox,
}

impl Mailer {
    pub fn new(transport: MailTransport, from_address: lettre::message::Mailbox) -> Self {
        Self {
            transport,
            from_address,
        }
    }
}

pub(crate) async fn send_activation_email(
    mailer: &Mailer,
    user: &crate::models::user::User,
) -> Result<(), AppError> {
    let Some(activation_token) = &user.activation_token else {
        return Err(anyhow::anyhow!("User does not have an activation token").into());
    };

    let message = Message::builder()
        .to(lettre::Address::from_str(&user.email)
            .context("Failed to parse email address")?
            .into())
        .from(mailer.from_address.clone())
        .subject("Activation code")
        .body(format!("Your activation code is: {}", activation_token))
        .context("Failed to generate email")?;
    mailer
        .transport
        .send(message)
        .await
        .context("Failed to send activation mail")?;
    Ok(())
}
