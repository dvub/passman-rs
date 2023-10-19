use crate::{crypto::*, error::*, password::{Password, PasswordField}};
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, OsRng},
    AeadCore, Aes256Gcm,
};
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension};
use thiserror::Error;

pub const MASTER_KEYWORD: &str = ".master";

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
        notes TEXT DEFAULT NULL
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
pub fn get_password(
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
fn decrypt_password(password: Password, master: &str) -> Result<Password, BackendError> {
    // fucking awesome partial struct destructuring
    let Password {
        id,
        name,
        .. // and the rest
    } = password;

    // this is not in the decrypt_field() function because it would involve deriving the key and generating the cipher 4 times
    // considering the iterations involved in the kdf function it would be extremely inefficient
    let cipher = gen_cipher(master, &name);

    // thank you @seaish for this fucking awesome function
    // ithis is so cool
    let f = |field: Option<String>| {
        field
            .map(|data| {
                let decoded_data = hex::decode(data)?;
                if decoded_data.len() < 12 {}
                let nonce = decoded_data
                    .get(..12)
                    .ok_or_else(|| BackendError::NoMatchingNonce)?;
                let ciphertext = decoded_data.get(12..).unwrap();
                decrypt_password_field(ciphertext, nonce, &cipher)
            })
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
) -> std::result::Result<std::option::Option<Password>, BackendError> {
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
    column_name: PasswordField,
    data: &str,
) -> std::result::Result<usize, BackendError> {
    let cipher = gen_cipher(master, password_name);
    let nonce: GenericArray<u8, typenum::U12> = Aes256Gcm::generate_nonce(OsRng);
    let mut n = nonce.to_vec();

    let mut encrypted = cipher.encrypt(&nonce, data.as_bytes()).unwrap();
    n.append(&mut encrypted);

    let ciphertext = hex::encode(n);

    let params = [password_name, ciphertext.as_str()];
    Ok(connection.execute(
        format!(
            "insert into password(name, {}) values (?1, ?2) on conflict(name) do update set {} = ?2 ",
            column_name, column_name
        )
        .as_str(),
        params,
    )?)
}



pub fn check_password_exists(connection: &Connection, name: &str) -> Result<bool, rusqlite::Error> {
    let mut stmt = connection.prepare("select * from password where name = ? ")?;
    let master_exists = stmt.query_row([name], |_| Ok(())).optional()?.is_some();
    Ok(master_exists)
}
pub fn authenticate(connection: &Connection, master: &str) -> Result<bool, BackendError> {
    // unwrapping values because these values MUST exist at this point in the application
    let record = get_password(connection, MASTER_KEYWORD)?
        .unwrap()
        .password
        .unwrap();

    Ok(hash(master.as_bytes()).to_vec() == hex::decode(record)?)
}

#[cfg(test)]
mod tests {
    use crate::crypto::derive_key;
    use aes_gcm::{
        aead::{generic_array::GenericArray, Aead, OsRng},
        AeadCore, Aes256Gcm, Key, KeyInit,
    };
    use rusqlite::Connection;

    fn insert_test_data(connection: &Connection) -> std::result::Result<usize, rusqlite::Error> {
        connection.execute(
            "insert into password (name, username, email, pass) VALUES (?1, ?2, ?3, ?4)",
            ("test_name", "cool_user1", "cool_user@usermail.com", "12345"),
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
        let derived = derive_key(master, name);
        let key = Key::<Aes256Gcm>::from_slice(&derived);
        let cipher = Aes256Gcm::new(key);

        let nonce: GenericArray<u8, typenum::U12> = Aes256Gcm::generate_nonce(OsRng);
        let mut n = nonce.to_vec();

        let mut encrypted = cipher.encrypt(&nonce, password.as_bytes()).unwrap();
        n.append(&mut encrypted);

        let ciphertext = hex::encode(n);

        let insert = connection
            .execute(
                "insert into password (name, pass) VALUES (?1, ?2)",
                (name, ciphertext),
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
        let connection = Connection::open_in_memory().unwrap();
        super::create_table(&connection).unwrap();

        let master = "mymasterpassword";
        let name = "test_name";
        let password = "coolpassword";

        super::insert_data(&connection, name, master, "pass", password).unwrap();

        let r = super::read_password(&connection, name, master)
            .unwrap()
            .unwrap();
        assert_eq!(r.password.unwrap(), password);
    }
}
