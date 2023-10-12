#[derive(Debug)]
struct Password {
    id: i32,
    name: String,
    email: Option<Vec<u8>>,
    username: Option<Vec<u8>>,
    password: Option<Vec<u8>>,
}
