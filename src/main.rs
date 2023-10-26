mod backend;
mod cli;

use cliclack::{intro, outro, select};
use colored::Colorize;

use backend::db_ops::{
    util::{check_password_info_exists, create_table, establish_connection},
    *,
};
use cli::{
    crud_operations::{delete, insert, read},
    utility::{insert_new_master_info, login},
    Operation,
};
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
