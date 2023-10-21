use cli::{delete, insert, insert_master, read, Operation};
use cliclack::{outro, password, select};

use crate::db_ops::*;

mod cli;
mod crypto;
mod db_ops;
mod error;
mod password;

use crate::db_ops::MASTER_KEYWORD;

// todo
// [x] refactor monolith frontend
// [] add nice colors to frontend

// GRAHH
// rework backend errors
// re-document backend

// FUNCTIONALITY
// add note field recovery method for master password
// create backup sqlite table for passwords

fn main() -> anyhow::Result<()> {
    let connection = establish_connection()?;
    create_table(&connection)?;

    let master_exists = check_password_exists(&connection, MASTER_KEYWORD)?;
    if !master_exists {
        insert_master(&connection, master_exists)?;
        return Ok(());
    }

    let master = password("Provide a master password").mask('*').interact()?;
    if !(authenticate(&connection, &master)?) {
        outro("Incorrect password. Exiting...")?;
        return Ok(());
    }

    let operation = select("What would you like to do?")
        .item(Operation::Insert, "Insert OR Update a password", "")
        .item(Operation::Read, "Get a password", "")
        .item(Operation::Delete, "Delete a password", "dangerous")
        .item(Operation::Exit, "Exit", "")
        .interact()?;

    match operation {
        Operation::Insert => insert(&connection, &master)?,
        Operation::Read => read(&connection, &master)?,
        Operation::Delete => delete(&connection)?,
        Operation::Exit => outro("Exiting...")?,
    }

    Ok(())
}
