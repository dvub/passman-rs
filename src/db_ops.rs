use crate::{
    crypto::*,
    error::*,
    password::{Password, PasswordColumn},
};
use aes_gcm::{
    aead::{KeyInit, OsRng},
    AeadCore, Aes256Gcm, Key,
};
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension};

const MASTER_KEYWORD: &str = ".master";

/// Establishes a connection to the SQLite database
pub fn establish_connection() -> std::result::Result<rusqlite::Connection, rusqlite::Error> {
    Connection::open("./data.db")
}

/// Creates the SQLite table equivelant of the `Password` struct.
pub fn create_table(connection: &Connection) -> std::result::Result<usize, rusqlite::Error> {
    connection.execute(
        "create table if not exists password(
        id INTEGER NOT NULL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        username TEXT DEFAULT NULL,
        email TEXT DEFAULT NULL,
        pass TEXT DEFAULT NULL,
        notes TEXT DEFAULT NULL,

        username_nonce TEXT DEFAULT NULL,
        email_nonce TEXT DEFAULT NULL,
        pass_nonce TEXT DEFAULT NULL,
        notes_nonce TEXT DEFAULT NULL

      );",
        (),
    )
}
/// Reads a `Password` from the SQLite database. The password should contain encrypted fields.
/// This function may fail with `rusqlite::Error`. Otherwise it will return an `Option<Password>`, being none if no password is found with the given search term.
///
/// # Arguments
///
/// - `connection` - a reference to a `rusqlite::Connection`, which may be to a file or in memory.
/// - `search_term` - a string slice that holds the name of the password to search for.
///
fn get_password(
    connection: &Connection,
    search_term: &str,
) -> Result<Option<Password>, rusqlite::Error> {
    let mut stmt = connection.prepare("select * from password where name = ?")?;
    stmt.query_row([search_term], |row| {
        Ok(Password {
            id: row.get(0)?,

            name: row.get(1)?,
            email: row.get(2)?,
            username: row.get(3)?,
            password: row.get(4)?,
            notes: row.get(5)?,

            email_nonce: row.get(6)?,
            username_nonce: row.get(7)?,
            password_nonce: row.get(8)?,
            notes_nonce: row.get(9)?,
        })
    })
    .optional()
}
/// Decrypts a `Password`, which is assumed to already contain encrypted data.
/// This function will return a result with a `GetPasswordError` if any step in the decryption process fails;
/// Otherwise the function will return a `Password` with decrypted fields.
///
/// # Arguments
///
/// - `password` - A `Password` with encrypted fields.
/// - `master` - a string slice that holds the master password.
///
fn decrypt_password(password: Password, master: &str) -> Result<Password, GetPasswordError> {
    // fucking awesome partial struct destructuring
    let Password {
        id,
        name,
        email_nonce,
        username_nonce,
        password_nonce,
        notes_nonce,
        .. // and the rest
    } = password;

    // this is not in the decrypt_field() function because it would involve deriving the key and generating the cipher 4 times
    // considering the iterations involved in the kdf function it would be extremely inefficient
    let cipher = gen_cipher(master, &name);

    // thank you @seaish for this fucking awesome function
    // ithis is so cool
    let f = |field: Option<String>, nonce: &Option<String>| {
        field
            .map(|data| {
                let resulted_nonce = nonce
                    .as_ref()
                    .ok_or_else(|| GetPasswordError::NoMatchingNonce)?;

                let decoded_nonce = hex::decode(resulted_nonce)?;

                decrypt_password_field(&data, &decoded_nonce, &cipher)
            })
            .transpose() // transpose switches "...the Option of a Result to a Result of an Option." ... that is so cool!!
    };

    let email = f(password.email, &email_nonce)?;
    let username = f(password.username, &username_nonce)?;
    let pass = f(password.password, &password_nonce)?;
    let notes = f(password.notes, &notes_nonce)?;

    Ok(Password {
        id,
        name,
        email,
        username,
        notes,
        password: pass,
        username_nonce,
        email_nonce,
        password_nonce,
        notes_nonce,
    })
}
/// Reads and decrypts a password from the SQLite database.
/// This function will return a result with the `GetPasswordError` enum, which wraps an `Option`;
/// If no `Password` name matches the given `search_term`, the function will return `None`.
/// # Arguments
///
/// - `connection` - a reference to a `rusqlite::Connection`, which may be to a file or in memory.
/// - `search_term` - a string slice that holds the name of the password to search for.
/// - `master` - a string slice holding the master password.
///
pub fn read_password(
    connection: &Connection,
    search_term: &str,
    master: &str,
) -> std::result::Result<std::option::Option<Password>, GetPasswordError> {
    // interestingly this function is just a combination of 2 other functions..
    get_password(connection, search_term)?
        .map(|encrypted| decrypt_password(encrypted, master))
        .transpose()
}
/// Encrypts and inserts a field into the SQLite database.
/// This function makes use of SQLite's `UPSERT` statement, i.e. create an entry with the given value to insert, or update an existing entry.
/// (Note: this function serves the purpose of Updating and Creating within the CRUD model)
/// This function will return a result with the `InsertEncryptedFieldError` enum.
/// If the function is successful it will return a `usize` of how many entries were updated - should be 1.
/// # Arguments
///
/// - `connection` - a reference to a `rusqlite::Connection`, which may be to a file or in memory.
/// - `password_name` - a string slice that holds the name of the password to insert or update into.
/// - `column_name` - a string slice holding the column to insert or update into.
/// - `master` - a string slice holding the master password.
/// - `column_name` - a `PasswordColumn` to insert or update data into.
/// - `data` - a string slice holding the data to encrypt and insert into the entry.
///
pub fn insert_data(
    connection: &Connection,
    password_name: &str,
    master: &str,
    column_name: PasswordColumn,
    data: &str,
) -> std::result::Result<usize, InsertEncryptedFieldError> {
    let column_name = match column_name {
        PasswordColumn::Email => "email",
        PasswordColumn::Username => "username",
        PasswordColumn::Notes => "notes",
        PasswordColumn::Password => "pass",
    };
    let cipher = gen_cipher(master, password_name);

    let nonce = Aes256Gcm::generate_nonce(OsRng);
    let encoded_nonce = hex::encode(nonce);

    let encrypted_data =
        encrypt_password_field(data, &nonce, &cipher).map_err(InsertEncryptedFieldError::AesGcm)?;

    let params = [
        password_name,
        encrypted_data.as_str(),
        encoded_nonce.as_str(),
    ];
    Ok(connection.execute(
        format!(
            "insert into password(name, {}, {}_nonce) values (?1, ?2, ?3) on conflict(name) do update set {} = ?3 ",
            column_name, column_name, column_name
        )
        .as_str(),
        params,
    )?)
}
pub fn check_master(connection: &Connection) -> Result<bool, rusqlite::Error> {
    let mut stmt = connection.prepare("select * from password where name = ? ")?;
    Ok(stmt
        .query_row([MASTER_KEYWORD], |_| Ok(true))
        .optional()?
        .is_some())
}

#[cfg(test)]
mod tests {
    use super::MASTER_KEYWORD;
    use crate::crypto::derive_key;
    use aes_gcm::{
        aead::{Aead, OsRng},
        AeadCore, Aes256Gcm, Key, KeyInit,
    };
    use rusqlite::Connection;

    fn insert_test_data(connection: &Connection) -> std::result::Result<usize, rusqlite::Error> {
        connection.execute(
            "insert into password (name, username, email, pass, username_nonce, email_nonce, pass_nonce) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                "test_name",
                "cool_user1",
                "cool_user@usermail.com",
                "12345",
                "nonce42",
                "nonce42",
                "nonce42",
            ),
        )
    }

    #[test]
    fn establish_connection() {
        assert!(super::establish_connection().is_ok());
    }
    #[test]
    fn create_table() {
        assert!(super::create_table(&Connection::open_in_memory().unwrap()).is_ok());
    }
    #[test]
    fn test_data() {
        let connection = Connection::open_in_memory().unwrap();
        super::create_table(&connection).unwrap();

        // just make sure that the insert test data function is working and inserts a row
        let insert_result = insert_test_data(&connection).unwrap();
        assert_eq!(insert_result, 1);
    }
    #[test]
    fn read_password() {
        let connection = Connection::open_in_memory().unwrap();
        super::create_table(&connection).unwrap();

        let master = "mymasterpassword";
        let name = "test_name";
        let password = "coolpassword";
        let derived_key = derive_key(master, name);

        let key = Key::<Aes256Gcm>::from_slice(&derived_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let encoded_nonce = hex::encode(nonce);

        let encrypted = hex::encode(cipher.encrypt(&nonce, password.as_bytes()).unwrap());
        let insert = connection
            .execute(
                "insert into password (name, pass, pass_nonce) VALUES (?1, ?2, ?3)",
                (name, encrypted, encoded_nonce),
            )
            .unwrap();
        assert_eq!(insert, 1);

        let res = super::read_password(&connection, name, master).unwrap();

        assert_eq!(
            res.expect("no password found")
                .password
                .expect("no password field"),
            password
        );
    }
    #[test]
    fn insert_data() {
        use super::PasswordColumn;
        let connection = Connection::open_in_memory().unwrap();
        super::create_table(&connection).unwrap();

        let master = "mymasterpassword";
        let name = "test_name";
        let password = "coolpassword";

        super::insert_data(
            &connection,
            name,
            master,
            PasswordColumn::Password,
            password,
        )
        .unwrap();

        let r = super::read_password(&connection, name, master)
            .unwrap()
            .unwrap();
        assert_eq!(r.password.unwrap(), password);
    }
    #[test]
    fn check_master() {
        let connection = Connection::open_in_memory().unwrap();
        super::create_table(&connection).unwrap();
        assert!(!super::check_master(&connection).unwrap());
        connection
            .execute(
                "insert into password(name, pass) values (?1, ?2)",
                [MASTER_KEYWORD, "mymasterpassword"],
            )
            .unwrap();
        assert!(super::check_master(&connection).unwrap());
    }
}
