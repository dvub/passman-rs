use std::io;

use cliclack::{input, password, select, confirm, outro, note};
use rusqlite::Connection;

use crate::crypto::{generate_password, hash};
use crate::db_ops::*;

mod crypto;
mod db_ops;
mod error;
mod password;

use crate::db_ops::MASTER_KEYWORD;
fn main() -> anyhow::Result<()> {
    
    let connection = establish_connection()?;
    println!("Connected to SQLite database.");

    create_table(&connection)?;

    let master_exists = check_password_exists(&connection, MASTER_KEYWORD)?;
    if !master_exists {
        println!("No master record.");
        println!();

        let new_master = "".to_string();
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

    println!("Found master record.");
    println!();
    let master = password("Provide a master password").mask('*').interact()?;

    if !(authenticate(&connection, &master)?) {
        outro("Incorrect password. Try again!")?;
        std::process::exit(1);
    }

    let operation = select("What would you like to do?")
        .item("create_update", "Insert OR Update a password", "")
        .item("read", "Get a password", "")
        .item("delete", "Delete a password", "dangerous")
        .interact()?;

    match operation {
        "create_update" => {
            let name: String = input("Enter Password name?")
                .placeholder("My new password")
                .required(true)
                .interact()?;
            
            if get_password(&connection, &name)?.is_some() {
                let confirm = confirm("A password already exists with this name. Would you like to update it?").interact()?;
                if !confirm {
                    std::process::exit(1);
                }
                note("Note", "If you do not messagewish to update a particular field, leave the value empty.")?;
                

            } else {
                note("Name is available", "This name is available. (no password was found with that name) Continuing will create a new password.")?;
            }
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
                "automatic"=> {
                    let length: String = input("Enter password length")
                        .default_input("12")
                        .placeholder("Your password length")
                        .validate(|input: &String| {
                            let num = input.parse::<i32>();

                            if num.is_err() {
                                Err("Please enter a number.")
                            } else {
                                Ok(())
                            }
                        })
                        .interact()?;
                    let num = length.parse::<usize>().unwrap();
                    let pass = generate_password(num);
                    insert_data(&connection, &name, &master, "pass", &pass)?;
                }
                "manual" => {}
                "none" => {}
                &_ => {}
            }
        }
        "read" => {
            let name: String = input("Enter Password name?")
            .placeholder("My new password")
            .required(true)
            .interact()?;
            let res = read_password(&connection, &name, &master)?;
            match res {
                Some(password) => {
                    let data = [
                        password.email,
                        password.username,
                        password.password,
                        password.notes,
                    ];
                    // FP (ftw) to check if the array of password fields contains only `none` and print a message
                    if data.iter().all(|field| field.is_none()) {
                        println!();
                        println!("no other data found for this record");
                    }
                
                    for (index, field) in data.iter().enumerate() {
                        match field {
                            Some(m) => {
                                let name = match index {
                                    0 => "email",
                                    1 => "username",
                                    2 => "password",
                                    3 => "notes",
                                    _ => "",
                                };
                                println!("{}: {}", name, m);
                            }
                            None => {}
                        }
                    }
                }
                None => println!("no password found with that name")
            }
        }
        "update" => {}
        "delete" => {}
        &_ => {}
    }

    outro("You're all set!")?;

    Ok(())
}

pub fn confirmed_password() -> Result<String, io::Error> {
    let mut new_password = "".to_string();
    let mut confirm = "0".to_string();
    while new_password != confirm {
        new_password = password("Provide a new master password")
            .mask('*')
            .interact()
            ?;
        confirm = password("Confirm new master password")
            .mask('*')
            .interact()?;
    }
    Ok(new_password)
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
        insert_data(connection, name, master, param, &data)?;
    }
    Ok(())
}
