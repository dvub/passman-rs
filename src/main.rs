mod backend;
mod cli;

use cliclack::{intro, outro, select};
use colored::Colorize;

use backend::db_ops::{
    util::{check_password_info_exists, create_table, establish_connection},
    MASTER_KEYWORD,
};
use cli::{
    crud_operations::{delete, insert, read},
    utility::{insert_new_master_info, login},
    Operation,
};

// TODO:
// implement bcrypt or argon or some shit for hashing, beccause youre fuckin stupid for using sha
// implement zeroize because uh .. safety... or something
// add logic for changing master password
// refactor project structure - simplify, because you overdid it
// rework error handling to use a few unwraps / expects where necessary/important.

// very simple main program, yay!
fn main() -> anyhow::Result<()> {
    let connection = establish_connection()?;

    create_table(&connection)?;

    intro("passman.rs")?;

    if !check_password_info_exists(&connection, MASTER_KEYWORD)? {
        insert_new_master_info(&connection)?;
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
        Operation::Insert => insert(&connection, &master)
            .unwrap_or_else(|f| eprintln!("There was an error updating the database:\n{}", f)),
        Operation::Read => read(&connection, &master)
            .unwrap_or_else(|f| eprintln!("There was an error reading the password:\n{}", f)),
        Operation::Delete => delete(&connection)
            .unwrap_or_else(|f| eprintln!("There was an error deleting the password:\n{}", f)),
        Operation::Exit => outro("Exiting...".green().bold())?,
    }
    Ok(())
}
