use std::str::FromStr;

use askama::Template;
use eyre::Context;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::{config::BaseUrl, error::AppError, routes::auth::ResetPasswordQuery};

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
#[template(path = "email/activation.txt.j2", escape = "txt")]
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

#[derive(Template)]
#[template(path = "email/password_reset.txt.j2", escape = "txt")]
struct PasswordResetTemplate<'a> {
    user: &'a crate::models::user::User,
    reset_url: &'a str,
}

pub(crate) async fn send_password_reset_email(
    mailer: &Mailer,
    user: &crate::models::user::User,
    token: &str,
    base_url: &BaseUrl,
) -> Result<(), AppError> {
    let qs = serde_qs::to_string(&ResetPasswordQuery {
        token: token.to_string(),
        email: user.email.clone(),
    })
    .wrap_err("Failed to serialize query string")?;
    let body_content = PasswordResetTemplate {
        user,
        reset_url: &format!("{}/login/reset-password?{qs}", base_url),
    }
    .render()
    .wrap_err("Failed to render password reset email")?;

    let message = Message::builder()
        .to(lettre::Address::from_str(&user.email)
            .wrap_err("Failed to parse email address")?
            .into())
        .from(mailer.from_address.clone())
        .subject("Password reset code")
        .body(body_content)
        .wrap_err("Failed to generate email")?;
    mailer
        .transport
        .send(message)
        .await
        .wrap_err("Failed to send password reset mail")?;
    Ok(())
}
