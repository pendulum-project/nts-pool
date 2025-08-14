use std::str::FromStr;

use askama::Template;
use eyre::Context;
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

#[derive(Template)]
#[template(path = "email/activation.txt.j2")]
struct ActivationTemplate<'a> {
    user: &'a crate::models::user::User,
    activation_token: &'a str,
}

pub(crate) async fn send_activation_email(
    mailer: &Mailer,
    user: &crate::models::user::User,
) -> Result<(), AppError> {
    let Some(activation_token) = &user.activation_token else {
        return Err(eyre::eyre!("User does not have an activation token").into());
    };

    let body_content = ActivationTemplate {
        user,
        activation_token,
    }
    .render()
    .wrap_err("Failed to render activation email")?;

    let message = Message::builder()
        .to(lettre::Address::from_str(&user.email)
            .wrap_err("Failed to parse email address")?
            .into())
        .from(mailer.from_address.clone())
        .subject("Activation code")
        .body(body_content)
        .wrap_err("Failed to generate email")?;
    mailer
        .transport
        .send(message)
        .await
        .wrap_err("Failed to send activation mail")?;
    Ok(())
}
