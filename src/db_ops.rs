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
    column_name: &str,
    search_term: &str,
) -> Result<Option<Password>, rusqlite::Error> {
    let mut statement =
        connection.prepare(format!("select * from password where {} = ?", column_name).as_str())?;

    statement
        .query_row([search_term], |row| {
            Ok(Password {
                id: row.get(0)?,
                name: row.get(1)?,
                username: row.get(2)?,
                email: row.get(3)?,
                password: row.get(4)?,
                notes: row.get(5)?,
                nonce: row.get(6)?,
            })
        })
        .optional()
}
pub fn insert_or_update(
    connection: &Connection,
    password_name: &str,
    column_name: &str,
    data: &str,
) {
    let statement = connection
        .execute("insert into password({}) values (?) on conflict({}) do update set {}=? ");
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
        // basically just util functions
        let connection = Connection::open_in_memory().unwrap();
        super::create_table(&connection).unwrap();
        insert_test_data(&connection).unwrap();

        let term = "test_name";
        // this is the important function that we want to test
        let result = super::get_password(&connection, "name", term)
            .unwrap()
            .unwrap();
        // check that the values are as we set them in the test function
        assert_eq!(result.name, term);
        assert!(result.notes.is_none());
    }
}
