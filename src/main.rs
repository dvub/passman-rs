use cli::{delete, insert, insert_master, read, Operation};
use cliclack::{intro, outro, password, select};
use colored::Colorize;

use crate::db_ops::*;

mod cli;
mod crypto;
mod db_ops;
mod error;
mod password;

use crate::db_ops::MASTER_KEYWORD;

// todo
// [x] refactor monolith frontend
// [~] add nice colors to frontend

// GRAHH
// [x] re-document backend
// write the remaining tests for db_ops.rs

// FUNCTIONALITY
// add note field recovery method for master password

// SPEED
// benchmarking

fn main() -> anyhow::Result<()> {
    let connection = establish_connection()?;
    create_table(&connection)?;

    intro("passman.rs")?;

    if !check_password_exists(&connection, MASTER_KEYWORD)? {
        insert_master(&connection)?;
        return Ok(());
    }

    let master = password(format!("Enter {}", "master password:".bright_red().bold()))
        .mask('*')
        .interact()?;
    if !(authenticate(&connection, &master)?) {
        outro("Incorrect password. Exiting...".red().bold())?;
        return Ok(());
    }

    let operation = select("What would you like to do?")
        .item(Operation::Insert, "Insert or Update a password", "")
        .item(Operation::Read, "Get a password", "")
        .item(Operation::Delete, "Delete a password", "dangerous")
        .item(Operation::Exit, "Exit", "")
        .interact()?;

    match operation {
        Operation::Insert => insert(&connection, &master)?,
        Operation::Read => read(&connection, &master)?,
        Operation::Delete => delete(&connection)?,
        Operation::Exit => outro("Exiting...".green().bold())?,
    }

    Ok(())
}
