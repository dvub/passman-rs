pub const MASTER_KEYWORD: &str = ".master";
pub mod crud {
    use crate::backend::{
        crypto::*,
        error::*,
        password::{PasswordField, PasswordInfo},
    };
    use aes_gcm::{
        aead::{generic_array::GenericArray, Aead, OsRng},
        AeadCore, Aes256Gcm,
    };
    use rusqlite::{Connection, OptionalExtension};
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
    ) -> Result<Option<PasswordInfo>, rusqlite::Error> {
        let mut stmt = connection.prepare("select * from PasswordInfo where name = ?")?;
        stmt.query_row([search_term], |row| {
            Ok(PasswordInfo {
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
    /// - `master` - a string slice that holds the master password. The master password should be verified/authenticated by the time this function is called.
    ///
    fn decrypt_password(
        password: PasswordInfo,
        master: &str,
    ) -> Result<PasswordInfo, BackendError> {
        // fucking awesome partial struct destructuring
        let PasswordInfo {
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

        Ok(PasswordInfo {
            id,
            name,
            email,
            username,
            notes,
            password: pass,
        })
    }

    // the following are functions that implement CRUD (create, read, update, delete)

    /// Reads and decrypts a password from the SQLite table `PasswordInfo`.
    /// This function will return a result with the `GetPasswordError` enum, which wraps an `Option`;
    /// If no `Password` name matches the given `search_term`, the function will return `None`.
    /// # Arguments
    ///
    /// - `connection` - a reference to a `rusqlite::Connection`, which may be to a file or in memory.
    /// - `search_term` - a string slice that holds the name of the password to search for.
    /// - `master` - a string slice holding the master password. The master password should be verified/authenticated by the time this function is called.
    ///
    pub fn read_password(
        connection: &Connection,
        search_term: &str,
        master: &str,
    ) -> std::result::Result<std::option::Option<PasswordInfo>, BackendError> {
        // interestingly this function is just a combination of 2 other functions..
        get_password(connection, search_term)?
            .map(|encrypted| decrypt_password(encrypted, master))
            .transpose()
    }
    /// Encrypts and inserts a field into the SQLite table `PasswordInfo`.
    /// This function makes use of SQLite's `UPSERT` statement, i.e. create an entry with the given value to insert, or update an existing entry.
    /// (Note: this function serves the purpose of Updating and Creating within the CRUD model)
    /// This function will return a result with the `InsertEncryptedFieldError` enum.
    /// If the function is successful it will return a `usize` of how many entries were updated - should be 1.
    /// # Arguments
    ///
    /// - `connection` - a reference to a `rusqlite::Connection`, which may be to a file or in memory.
    /// - `password_name` - a string slice that holds the name of the password to insert or update into.
    /// - `master` - a string slice holding the master password. The master password should be verified/authenticated by the time this function is called.
    /// - `column_name` - a `PasswordField` to insert or update data into.
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
                "insert into PasswordInfo(name, {}) values (?1, ?2) on conflict(name) do update set {} = ?2 ",
                column_name, column_name
            )
            .as_str(),
            params,
        )?)
    }

    /// Deletes one record from the SQLite table `PasswordInfo` Use with caution!.
    ///  # Arguments
    ///
    /// - `connection` - a reference to a `rusqlite::Connection`, which may be to a file or in memory.
    /// - `password_name` - a string slice that holds the name of the password to insert or update into.
    ///
    pub fn delete_password(
        connection: &Connection,
        password_name: &str,
    ) -> Result<usize, rusqlite::Error> {
        connection.execute("delete from PasswordInfo where name = ?", [password_name])
    }
}
pub mod util {
    use crate::backend::{crypto::*, error::*, password::PasswordField};

    use rusqlite::{Connection, OptionalExtension};

    use super::{crud::get_password, MASTER_KEYWORD};
    /// Establishes a connection to the SQLite database
    pub fn establish_connection() -> Result<rusqlite::Connection, rusqlite::Error> {
        Connection::open("./data.db")
    }

    /// Creates the SQLite table equivelant of the `Password` struct.
    pub fn create_table(connection: &Connection) -> Result<usize, rusqlite::Error> {
        connection.execute(
            "CREATE TABLE IF NOT EXISTS PasswordInfo (
        id INTEGER NOT NULL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        username TEXT DEFAULT NULL,
        email TEXT DEFAULT NULL,
        password TEXT DEFAULT NULL,
        notes TEXT DEFAULT NULL
      );",
            (),
        )
    }

    /// Check if a password exists. May fail with `rusqlite::Error`.
    /// Checks if an `optional()` query `is_some()`, i.e. returns `false` if `None`.
    /// ///  # Arguments
    ///
    /// - `connection` - a reference to a `rusqlite::Connection`, which may be to a file or in memory.
    /// - `password_name` - a string slice that holds the name of the password to insert or update into.
    ///
    pub fn check_password_exists(
        connection: &Connection,
        password_name: &str,
    ) -> Result<bool, rusqlite::Error> {
        let mut stmt = connection.prepare("select * from PasswordInfo where name = ? ")?;
        let master_exists = stmt
            .query_row([password_name], |_| Ok(()))
            .optional()?
            .is_some();
        Ok(master_exists)
    }
    /// Check if a password exists. May fail with `rusqlite::Error`.
    /// Checks if an `optional()` query `is_some()`, i.e. returns `false` if `None`.
    /// ///  # Arguments
    ///
    /// - `connection` - a reference to a `rusqlite::Connection`, which may be to a file or in memory.
    /// - `master` - a string slice that holds the master password.
    ///
    pub fn authenticate(
        connection: &Connection,
        master: &str,
        column: PasswordField,
    ) -> Result<bool, BackendError> {
        // unwrapping values because these values MUST exist at this point in the application
        let master_record = get_password(connection, MASTER_KEYWORD)?.unwrap();
        let data = match column {
            PasswordField::Password => Ok(master_record.password.unwrap()),
            PasswordField::Notes => Ok(master_record.notes.unwrap()),
            _ => Err(BackendError::InvalidMasterRecordField),
        }?;

        Ok(hash(master.as_bytes()).to_vec() == hex::decode(data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::MASTER_KEYWORD;
    use crate::{
        backend::crypto::derive_key,
        backend::{crypto::hash, password::PasswordField},
    };
    use aes_gcm::{
        aead::{generic_array::GenericArray, Aead, OsRng},
        AeadCore, Aes256Gcm, Key, KeyInit,
    };
    use rusqlite::Connection;
    fn insert_test_data(connection: &Connection) -> std::result::Result<usize, rusqlite::Error> {
        connection.execute(
            "insert into PasswordInfo (name, username, email, password) VALUES (?1, ?2, ?3, ?4)",
            ("test_name", "cool_user1", "cool_user@usermail.com", "12345"),
        )
    }

    #[test]
    fn establish_connection() {
        assert!(super::util::establish_connection().is_ok());
    }
    #[test]
    fn create_table() {
        assert!(super::util::create_table(&Connection::open_in_memory().unwrap()).is_ok());
    }
    #[test]
    fn test_data() {
        let connection = Connection::open_in_memory().unwrap();
        super::util::create_table(&connection).unwrap();

        // just make sure that the insert test data function is working and inserts a row
        let insert_result = insert_test_data(&connection).unwrap();
        assert_eq!(insert_result, 1);
    }
    #[test]
    fn read_password() {
        let connection = Connection::open_in_memory().unwrap();
        super::util::create_table(&connection).unwrap();

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
                "insert into PasswordInfo (name, password) VALUES (?1, ?2)",
                (name, ciphertext),
            )
            .unwrap();
        assert_eq!(insert, 1);

        let res = super::crud::read_password(&connection, name, master).unwrap();

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
        super::util::create_table(&connection).unwrap();

        let master = "mymasterpassword";
        let name = "test_name";
        let password = "coolpassword";

        super::crud::insert_data(&connection, name, master, PasswordField::Password, password)
            .unwrap();

        let r = super::crud::read_password(&connection, name, master)
            .unwrap()
            .unwrap();
        assert_eq!(r.password.unwrap(), password);
    }
    #[test]
    fn delete() {
        let connection = Connection::open_in_memory().unwrap();
        super::util::create_table(&connection).unwrap();

        let master = "mymasterpassword";
        let name = "test_name";
        let password = "coolpassword";

        super::crud::insert_data(&connection, name, master, PasswordField::Password, password)
            .unwrap();

        super::crud::delete_password(&connection, name).unwrap();
        let result = super::crud::read_password(&connection, name, master).unwrap();
        assert!(result.is_none())
    }
    #[test]
    fn check_exists() {
        let connection = Connection::open_in_memory().unwrap();
        super::util::create_table(&connection).unwrap();
        let master = "masterpassword";
        let name = "test";
        // first, make sure the function returns false if no data exists
        assert!(!super::util::check_password_exists(&connection, name).unwrap());
        // now lets insert some data
        super::crud::insert_data(
            &connection,
            name,
            master,
            PasswordField::Password,
            "supersecret",
        )
        .unwrap();
        // finally, we'll check one more time to make sure it's returning true since we added data
        assert!(super::util::check_password_exists(&connection, name).unwrap());
    }
    #[test]
    fn authenticate() {
        let connection = Connection::open_in_memory().unwrap();
        super::util::create_table(&connection).unwrap();
        let new_master = "mymasterpassword";
        let recovery_note = "abcd";

        // ripped from cli.rs
        let master_password = hex::encode(hash(new_master.as_bytes()));
        let note = hex::encode(hash(recovery_note.as_bytes()));

        connection
            .execute(
                "insert into PasswordInfo (name, password, notes) values (?1, ?2, ?3)",
                [MASTER_KEYWORD, &master_password, &note],
            )
            .unwrap();

        assert!(super::util::authenticate(
            &connection,
            "mymasterpassword",
            PasswordField::Password
        )
        .unwrap());
        assert!(
            !super::util::authenticate(&connection, "random_guess", PasswordField::Password)
                .unwrap()
        );
    }
}
