mod backend;
mod cli;

use cliclack::{intro, outro, select};
use colored::Colorize;

use backend::db_ops::{
    util::{check_password_exists, create_table, establish_connection},
    *,
};
use cli::{
    crud::{delete, insert, read},
    util::{insert_master, login},
    Operation,
};

// todo
// [x] refactor monolith frontend
// [~] add nice colors to frontend

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
    let master = login(&connection)?;

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
