use std::process;

use cliclack::{input, log, multiselect, password, select, clear_screen};
use rusqlite::OptionalExtension;

use crate::crypto::hash;
use crate::db_ops::*;

mod crypto;
mod db_ops;
mod error;
mod password;

use crate::db_ops::MASTER_KEYWORD;
fn main() -> anyhow::Result<()> {
    use cliclack::{intro, outro};


    println!("Connecting to SQLite database...");

    let connection = establish_connection().unwrap_or_else(|e| {
        eprintln!("There was an error: {}", e);
        process::exit(1);
    });
    println!("Connected to SQLite database");

    println!("Querying Password Table...");
    create_table(&connection).unwrap_or_else(|e| {
        eprintln!("There was an error: {}", e);
        std::process::exit(1);
    });

    println!("Found Password table");

    let mut stmt = connection.prepare("select * from password where name = ? ")?;
    let master_exists = stmt
        .query_row([MASTER_KEYWORD], |_| Ok(true))
        .optional()?
        .is_some();

    println!("Checking master record...");
    if !master_exists {
        println!("master does not exist!");
        println!();

        let mut new_master = "".to_string();
        let mut confirm = "0".to_string();
        while new_master != confirm {
            new_master = password("Provide a new master password")
                .mask('*')
                .interact()?;
            confirm = password("Confirm new master password")
                .mask('*')
                .interact()?;
        }

        let master_password = hex::encode(hash(new_master.as_bytes()).to_vec());
        connection.execute(
            "insert into password (name, pass) values (?1, ?2)", 
            [MASTER_KEYWORD, &master_password]
        )?;
        println!();
        println!("successfully inserted new master record");
        std::process::exit(1);

    }

    println!("Found master record");
    let master = password("Provide a master password")
        .mask('▪')
        .interact()
        .unwrap();

    
    // unwrapping values because these values MUST exist at this point in the application
    let record = get_password(&connection, MASTER_KEYWORD)?.unwrap().password.unwrap();

    if hash(master.as_bytes()).to_vec() != hex::decode(record)? {
        eprintln!("incorrect password");
        std::process::exit(1);
    }


    let operation = select("What would you like to do?")
        .item("create", "Insert a new password", "")
        .item("read", "Get a password", "")
        .item("update", "Update a password", "")
        .item("delete", "Delete a password", "dangerous")
        .interact()
        .unwrap();

    match operation {
        create => {
            let name: String = input("Enter Password name?")
                .placeholder("My new password")
                .required(true)
                .interact()?;
            let params = vec!["email"];

            let email = input("Enter email (optional)")
                .placeholder("johndoe@emailprovider.com")
                .default_input("")
                .interact::<String>()?;
            if !email.is_empty() {
                insert_data(&connection, &name, &master, "email", &email)?;
            }
            
           
        }
        read => {}
        update => {}
        delete => {}
    }

    outro("You're all set!").unwrap();

    Ok(())
}
