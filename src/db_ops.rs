use crate::crypto::*;

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    Aes256Gcm, Key,
};
use rusqlite::{Connection, OptionalExtension};

#[derive(Debug)]
pub struct Password {
    id: i32,
    name: String,
    email: Option<String>,
    username: Option<String>,
    notes: Option<String>,
    password: Option<String>,
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

      );",
        (),
    )
}
pub fn get_password(
    connection: &Connection,
    master_password: impl AsRef<[u8]>,
    search_term: &str,
) -> Result<Option<Password>, rusqlite::Error> {
    let mut statement = connection.prepare("select * from password where name = ?")?;

    statement
        .query_row([search_term], |row| {
            let id: i32 = row.get(0)?;
            let name: Vec<u8> = row.get(1)?;
            let derived = derive_key(master_password, &name);
            let key = Key::<Aes256Gcm>::from_slice(&derived);
            let cipher = Aes256Gcm::new(key);

            let decrypted_data: Vec<Option<String>> = (2..5)
                .map(|n| {
                    let data: Option<String> = row.get(n).unwrap();

                    match data {
                        Some(data) => {
                            let decrypted = cipher
                                .decrypt(GenericArray::from_slice(&name), data.as_ref())
                                .unwrap();
                            Some(String::from_utf8(decrypted).unwrap())
                        }
                        None => None,
                    }
                })
                .collect();

            Ok(Password {
                id,
                name: row.get(1)?,
                username: row.get(2)?,
                email: row.get(3)?,
                password: row.get(4)?,
                notes: row.get(5)?,
            })
        })
        .optional()
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
    use rusqlite::Connection;

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

    // test the read function
    #[test]
    fn get_password() {
        let connection = test_setup();

        let term = "test_name";
        // this is the important function that we want to test
        let result = super::get_password(&connection, term).unwrap().unwrap();
        // check that the values are as we set them in the test function
        assert_eq!(result.name, term);
        assert!(result.notes.is_none());
    }
    // test the insert portion of the insert_data function
    #[test]
    fn insert() {
        let connection = test_setup();

        let result = super::insert_data(&connection, "test", "pass", "mypass123").unwrap();
        assert_eq!(result, 1);
        assert_eq!(
            super::get_password(&connection, "test")
                .unwrap()
                .unwrap()
                .password
                .unwrap(),
            "mypass123"
        );
    }
    // test the update portion of the insert_data function
    #[test]
    fn update() {
        let connection = test_setup();
        super::insert_data(&connection, "test_name", "pass", "mypass123").unwrap();
        let new_data = super::get_password(&connection, "test_name")
            .unwrap()
            .unwrap()
            .password
            .unwrap();
        assert_eq!(new_data, "mypass123");
    }
}
