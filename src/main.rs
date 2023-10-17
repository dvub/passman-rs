use std::process;

use cliclack::{input, log, multiselect, password, select};

use crate::db_ops::*;

mod crypto;
mod db_ops;
mod error;
mod password;

fn main() -> anyhow::Result<()> {
    use cliclack::{intro, outro};

    intro("passman")?;

    log::info("Connecting to SQLite database...")?;

    let connection = establish_connection().unwrap_or_else(|e| {
        eprintln!("There was an error: {}", e);
        process::exit(1);
    });
    log::success("Connected to SQLite database!")?;

    log::info("Querying Table")?;
    create_table(&connection).unwrap_or_else(|e| {
        eprintln!("There was an error: {}", e);
        std::process::exit(1);
    });

    log::success("Found database table!")?;

    let master_exists = check_master(&connection).unwrap_or_else(|e| {
        eprintln!("There was an error: {}", e);
        std::process::exit(1);
    });
    if !master_exists {
        log::error("master does not exist!")?;
        let mut new_master = "".to_string();
        let mut confirm = "".to_string();
        while new_master != confirm {
            new_master = password("Provide a new master password")
                .mask('*')
                .interact()?;
            confirm = password("Confirm new master password")
                .mask('*')
                .interact()?;
        }
    }

    let master = password("Provide a master password")
        .mask('▪')
        .interact()
        .unwrap();

    let operation = select("What would you like to do?")
        .item("create", "Insert a new password", "recommended")
        .item("read", "Get a password", "")
        .item("update", "Update a password", "")
        .item("delete", "Delete a password", "dangerous")
        .interact()
        .unwrap();

    match operation {
        create => {}
        read => {}
        update => {}
        delete => {}
    }

    outro("You're all set!").unwrap();

    Ok(())
}
