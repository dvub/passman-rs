use std::process;

use cliclack::{clear_screen, input, log, multiselect, password, select};
use rusqlite::{Connection, OptionalExtension};

use crate::crypto::{generate_password, hash};
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
    let master_exists = check_password_exists(&connection, MASTER_KEYWORD)?;
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

        let master_password = hex::encode(hash(new_master.as_bytes()));
        connection.execute(
            "insert into password (name, pass) values (?1, ?2)",
            [MASTER_KEYWORD, &master_password],
        )?;
        println!();
        println!("successfully inserted new master record");
        std::process::exit(1);
    }

    println!("Found master record");
    let master = password("Provide a master password").mask('▪').interact()?;

    if !(authenticate(&connection, &master)?) {
        eprintln!("Incorrect password");
        std::process::exit(1);
    }

    let operation = select("What would you like to do?")
        .item("create", "Insert a new password", "")
        .item("read", "Get a password", "")
        .item("update", "Update a password", "")
        .item("delete", "Delete a password", "dangerous")
        .interact()?;

    match operation {
        create => {
            let name: String = input("Enter Password name?")
                .placeholder("My new password")
                .required(true)
                .interact()?;

            //
            prompt_field(&connection, &master, &name, "email", "jdoe@myemail.com")?;
            prompt_field(&connection, &master, &name, "username", "John_Doe")?;
            prompt_field(&connection, &master, &name, "notes", "any text here")?;
            //

            let password_type = select("Select password generation type (optional)")
                .item(
                    "automatic",
                    "Generate a password for me",
                    "secure & recommended",
                )
                .item("manual", "I'll type one myself", "not as secure")
                .item("none", "I don't want to write down a password", "")
                .interact()?;
            match password_type {
                automatic => {
                    let length: String = input("Enter password length")
                        .default_input("12")
                        .placeholder("Your password length")
                        .validate(|input: &String| {
                            if input.parse::<i32>().is_err() {
                                Err("Please enter a number.")
                            } else {
                                Ok(())
                            }
                        })
                        .interact()?;
                    let num = length.parse::<usize>().unwrap();
                    let pass = generate_password(num);
                    insert_data(&connection, &name, &master, "email", &pass)?;
                }
                manual => {}
                none => {}
            }
        }
        read => {}
        update => {}
        delete => {}
    }

    outro("You're all set!")?;

    Ok(())
}

pub fn prompt_field(
    connection: &Connection,
    master: &str,
    name: &str,
    param: &str,
    placeholder: &str,
) -> anyhow::Result<()> {
    let data = input(format!("Enter {} (optional)", param))
        .placeholder(placeholder)
        .default_input("")
        .interact::<String>()?;
    if !data.is_empty() {
        insert_data(connection, name, master, "email", &data)?;
    }
    Ok(())
}
