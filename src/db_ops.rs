use std::string::FromUtf8Error;

use crate::crypto::*;
use aes_gcm::{aead::KeyInit, Aes256Gcm, Key};
use anyhow::Result;
use hex::FromHexError;
use rusqlite::{Connection, OptionalExtension};
use thiserror::Error;

#[derive(Debug)]
/// A struct to represent a password
pub struct Password {
    /// Password ID, auto-incremented by SQLite database. do not set this yourself!
    id: i32,
    /// The password name. Must be unique or will fail SQLite constraints.
    name: String,
    /// Optional email field.
    email: Option<String>,
    /// Optional username field.
    username: Option<String>,
    /// Optional notes field.
    notes: Option<String>,
    /// Optional password field.
    password: Option<String>,
    /// Required nonce used for AES (GCM 256) decryption and encryption. Only generate nonces securely!!
    nonce: String,
}
#[derive(Error, Debug)]
/// Custom error `enum` for getting passwords.
/// Encapsulates every error that may occur during reading and decrypting a password from the SQLite database.
pub enum GetPasswordError {
    #[error("error decoding: {0}")]
    Decode(#[from] FromHexError),
    #[error("error converting decrypted data to a string: {0}")]
    ToString(#[from] FromUtf8Error),
    // this is so awesome:
    // at first i was having issues because i couldn't use `#[from] aes_gcm::Error,` (doesn't impl std error)
    // so instead i used it as an argument and then took the decrypt result and used `map_err()` with the aes_gcm error.
    #[error("error occurred during decryption: {0}")]
    AesGcm(aes_gcm::Error),
    #[error("error getting password from db: {0}")]
    SQLite(#[from] rusqlite::Error),
}
#[derive(Error, Debug)]
pub enum InsertEncryptedFieldError {
    #[error("error encrypting")]
    AesGcm(aes_gcm::Error),
    #[error("SQlite error: {0}")]
    SQLite(#[from] rusqlite::Error),
}

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
        nonce TEXT NOT NULL
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
            nonce: row.get(6)?,
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
    // idk why i did this part
    let id = password.id;
    let name = password.name;
    let nonce = password.nonce;

    // this is not in the decrypt_field() function because it would involve deriving the key and generating the cipher 4 times
    // considering the iterations involved in the kdf function it would be extremely inefficient
    let derived = derive_key(master, &name);
    let key = Key::<Aes256Gcm>::from_slice(&derived);
    let cipher = Aes256Gcm::new(key);

    let decoded_nonce = hex::decode(&nonce)?;

    // for the sake of documenting my coding skills, this was my original implementation

    /*
    let decrypted_data = [
        password.email,
        password.username,
        password.password,
        password.notes,
    ]
    .map(|field| match field {
        Some(data) => anyhow::Ok(Some(decrypt_password_field(
            &data,
            &decoded_nonce,
            &cipher,
        )?)),
        None => anyhow::Ok(None),
    });


    let [email, username, password, notes] = decrypted_data;
    let email = email?;
    let username = username?;
    let password = password?;
    let notes = notes?;
    */

    // thank you @seaish for this fucking awesome function
    // ithis is so cool
    let f = |field: Option<String>| {
        field
            .map(|data| decrypt_password_field(&data, &decoded_nonce, &cipher))
            .transpose() // transpose switches "...the Option of a Result to a Result of an Option." ... that is so cool!!
    };
    let email = f(password.email)?;
    let username = f(password.username)?;
    let pass = f(password.password)?;
    let notes = f(password.notes)?;
    Ok(Password {
        id,
        name,
        email,
        username,
        notes,
        password: pass,
        nonce,
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
/// - `data` - a string slice holding the data to encrypt and insert into the entry.
/// - `master` - a string slice holding the master password.
/// - `nonce` - a `GenericArray` holding the AES nonce.
///
pub fn insert_data(
    connection: &Connection,
    password_name: &str,
    column_name: &str,
    data: &str,
    master: &str,
    nonce: &Nonce,
) -> std::result::Result<usize, InsertEncryptedFieldError> {
    let encrypted_data = encrypt_password_field(password_name, column_name, data, master, nonce)
        .map_err(InsertEncryptedFieldError::AesGcm)?;

    Ok(connection.execute(
        format!(
            "insert into password(name, {}) values (?1, ?2) on conflict(name) do update set {} = ?3 ",
            column_name, column_name,
        )
        .as_str(),
        [password_name, encrypted_data.as_str(), encrypted_data.as_str()],
    )?)
}

pub fn insert_nonce(
    connection: &Connection,
    name: &str,
    nonce: Nonce,
) -> Result<usize, rusqlite::Error> {
    let encoded = hex::encode(nonce);

    connection.execute(
        "insert into password(name, nonce) values (?1, ?2) on conflict(name) do update set nonce = ?3",
        [name, &encoded, &encoded]
    )
}
#[cfg(test)]
mod tests {
    use aes_gcm::{
        aead::{Aead, OsRng},
        AeadCore, Aes256Gcm, Key, KeyInit,
    };
    use rusqlite::Connection;

    use crate::crypto::derive_key;

    fn insert_test_data(connection: &Connection) -> std::result::Result<usize, rusqlite::Error> {
        connection.execute(
            "insert into password (name, username, email, pass, nonce) VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                "test_name",
                "cool_user1",
                "cool_user@usermail.com",
                "12345",
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

        let plaintext_arr = ["cool_user1", "cool_user@usermail.com", password, "mynotes"];

        let encrypted_arr: Vec<String> = plaintext_arr
            .iter()
            .map(|data| hex::encode(cipher.encrypt(&nonce, data.as_bytes()).unwrap()))
            .collect();

        let insert = connection.execute(
            "insert into password (name, username, email, pass, notes, nonce) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                name,
                encrypted_arr.get(0).unwrap(),
                encrypted_arr.get(1).unwrap(),
                encrypted_arr.get(2).unwrap(),
                encrypted_arr.get(3).unwrap(),
                encoded_nonce,
            ),
        ).unwrap();
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
        let connection = Connection::open_in_memory().unwrap();
        super::create_table(&connection).unwrap();

        let master = "mymasterpassword";
        let name = "test_name";
        let password = "coolpassword";

        let nonce = Aes256Gcm::generate_nonce(OsRng);

        super::insert_nonce(&connection, name, nonce).unwrap();

        super::insert_data(&connection, name, "pass", password, master, &nonce).unwrap();

        let r = super::read_password(&connection, name, master)
            .unwrap()
            .unwrap();
        assert_eq!(r.password.unwrap(), password);
    }
    #[test]
    fn insert_nonce() {
        let connection = Connection::open_in_memory().unwrap();
        super::create_table(&connection).unwrap();

        let nonce = Aes256Gcm::generate_nonce(OsRng);
        assert_eq!(super::insert_nonce(&connection, "SHIT", nonce).unwrap(), 1);
        // this may seem redundant but i'm regenerating a nonce to make sure it's updating.
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        assert_eq!(super::insert_nonce(&connection, "SHIT", nonce).unwrap(), 1);
    }
}
