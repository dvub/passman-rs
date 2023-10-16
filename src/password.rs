#[derive(Debug)]
/// A struct to represent a password
pub struct Password {
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

    pub username_nonce: Option<String>,
    pub email_nonce: Option<String>,
    pub password_nonce: Option<String>,
    pub notes_nonce: Option<String>,
}

pub enum PasswordColumn {
    Email,
    Username,
    Password,
    Notes,
}
