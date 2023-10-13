use rusqlite::{params, Connection};

#[derive(Debug)]
struct Password {
    id: i32,
    name: String,
    email: Option<Vec<u8>>,
    username: Option<Vec<u8>>,
    notes: Option<Vec<u8>>,
    password: Option<Vec<u8>>,
    nonce: Vec<u8>,
}
pub fn establish_connection() -> std::result::Result<rusqlite::Connection, rusqlite::Error> {
    Connection::open("./data.db")
}
pub fn create_table(connection: Connection) -> std::result::Result<usize, rusqlite::Error> {
    connection.execute(
        "create table if not exists password(
        id INTEGER NOT NULL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        username TEXT DEFAULT NULL,
        email TEXT DEFAULT NULL,
        pass TEXT DEFAULT NULL,
        notes TEXT DEFAULT NULL,
        aes_nonce TEXT NOT NULL
      );",
        (),
    )
}
pub fn get_password(
    connection: Connection,
    name: String,
) -> std::result::Result<usize, rusqlite::Error> {
    let statement = connection
        .prepare("select * from password where name = ?;")
        .unwrap();
    statement.query(name);
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    #[test]
    fn establish_connection() {
        assert!(super::establish_connection().is_ok());
    }
    #[test]
    fn create_table() {
        let connection = Connection::open_in_memory().unwrap();
        let result = super::create_table(connection);
        assert!(result.is_ok());
    }
}
