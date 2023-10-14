use std::f32::consts::E;

use crate::crypto::*;

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    Aes256Gcm, Key,
};
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension};
#[derive(Debug)]
pub struct Password {
    id: i32,
    name: String,
    email: Option<String>,
    username: Option<String>,
    notes: Option<String>,
    password: Option<String>,
    nonce: String,
}

pub fn establish_connection() -> std::result::Result<rusqlite::Connection, rusqlite::Error> {
    Connection::open("./data.db")
}
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

pub fn get_password(
    connection: &Connection,
    master_password: impl AsRef<[u8]>,
    search_term: &str,
) -> anyhow::Result<Option<Password>> {
    let mut statement = connection.prepare("select * from password where name = ?")?;

    Ok(statement
        .query_row([search_term], |row| {
            // Get required data
            let id: i32 = row.get(0)?;
            let name: String = row.get(1)?;
            let nonce: String = row.get(6)?;

            let derived = derive_key(master_password, &name);
            let key = Key::<Aes256Gcm>::from_slice(&derived);
            let cipher = Aes256Gcm::new(key);

            let decrypted_data: Vec<Option<anyhow::Result<String>>> = (2..6)
                .map(|n| {
                    let data: Option<String> = row.get::<usize, Option<String>>(n)?;
                    match data {
                        Some(x) => {
                            let decoded = hex::decode(x)?;
                            let decoded_nonce = hex::decode(&nonce)?;

                            let decrypted = cipher
                                .decrypt(GenericArray::from_slice(&decoded_nonce), decoded.as_ref())
                                .unwrap();

                            Some(String::from_utf8(decrypted)?)
                        }
                        None => None,
                    }
                })
                .collect();

            Ok(Password {
                id,
                name,
                username: decrypted_data[0]?,
                email: decrypted_data.get(1).unwrap().unwrap().clone(),
                password: decrypted_data.get(2).unwrap().unwrap().clone(),
                notes: decrypted_data.get(3).unwrap().unwrap().clone(),
                nonce,
            })
        })
        .optional()?)
}
pub fn insert_data(
    connection: &Connection,
    password_name: &str,
    column_name: &str,
    data: &str,
) -> std::result::Result<usize, rusqlite::Error> {
    connection.execute(
        format!(
            "insert into password(name, {}) values (?1, ?2) on conflict(name) do update set {} = ?3 ",
            column_name, column_name,
        )
        .as_str(),
        [password_name, data, data],
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

    fn test_setup() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        super::create_table(&connection).unwrap();
        insert_test_data(&connection).unwrap();
        connection
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
    fn get_password() {
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

        let res = super::get_password(&connection, master, name).expect("error getting from db");

        assert_eq!(
            res.expect("no password found")
                .password
                .expect("no password field"),
            password
        );
    }
}
