use core::fmt;
use std::fmt::Display;

#[derive(Debug)]
/// A struct to represent a password
pub struct PasswordInfo {
    /// Password ID, auto-incremented by SQLite database. do not set this yourself!
    pub id: i32,
    /// The password name. Must be unique or will fail SQLite constraints.
    pub name: String,
    /// Optional email field.
    pub email: Option<String>,
    /// Optional username field.
    pub username: Option<String>,
    /// Optional notes field.
    pub notes: Option<String>,
    /// Optional password field.
    pub password: Option<String>,
}
#[derive(Debug)]
pub enum PasswordField {
    Email,
    Username,
    Notes,
    Password,
}

impl Display for PasswordField {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match self {
            PasswordField::Email => "email",
            PasswordField::Username => "username",
            PasswordField::Password => "pass",
            PasswordField::Notes => "notes",
        };
        write!(f, "{}", str)
    }
}
