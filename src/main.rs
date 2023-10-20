use std::io;

use cliclack::{confirm, input, log, note, outro, password, select};
use password::{PasswordField, PasswordInfo};
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

    create_table(&connection)?;

    let master_exists = check_password_exists(&connection, MASTER_KEYWORD)?;
    if !master_exists {
        let new_master = confirmed_password()?;

        let master_password = hex::encode(hash(new_master.as_bytes()));
        connection.execute(
            "insert into password (name, pass) values (?1, ?2)",
            [MASTER_KEYWORD, &master_password],
        )?;
        outro("Inserted a new master record! Exiting...")?;
        std::process::exit(1);
    }

    let master = password("Provide a master password").mask('*').interact()?;

    if !(authenticate(&connection, &master)?) {
        outro("Incorrect password. Exiting...")?;
        std::process::exit(1);
    }
    log::success("Successfully authenticated with master record.")?;

    let operation = select("What would you like to do?")
        .item(Operation::CreateOrUpdate, "Insert OR Update a password", "")
        .item(Operation::Read, "Get a password", "")
        .item(Operation::Delete, "Delete a password", "dangerous")
        .interact()?;

    match operation {
        Operation::CreateOrUpdate => {
            let name: String = input("Enter Password name?")
                .placeholder("My new password")
                .required(true)
                .interact()?;

            if get_password(&connection, &name)?.is_some() {
                let confirm = confirm(
                    "A password already exists with this name. Would you like to update it?",
                )
                .interact()?;
                if !confirm {
                    std::process::exit(1);
                }
                note("Note", "If you do not messagewish to update a particular field, leave the value empty.")?;
            } else {
                note(
                    "Name is available",
                    "This name is available. Continuing will insert a new password.",
                )?;
            }
            //
            prompt_field(
                &connection,
                &master,
                &name,
                PasswordField::Email,
                "example@domain.com",
            )?;
            prompt_field(
                &connection,
                &master,
                &name,
                PasswordField::Username,
                "example_username",
            )?;
            prompt_field(
                &connection,
                &master,
                &name,
                PasswordField::Notes,
                "any text here",
            )?;
            //
            let password_type: PasswordGeneration =
                select("Select password generation type (optional)")
                    .item(
                        PasswordGeneration::Automatic,
                        "Generate a password for me",
                        "secure & recommended",
                    )
                    .item(
                        PasswordGeneration::Manual,
                        "I'll type one myself",
                        "not as secure",
                    )
                    .item(
                        PasswordGeneration::NoPassword,
                        "I don't want to save a password",
                        "",
                    )
                    .interact()?;
            let password: Option<String> = match password_type {
                PasswordGeneration::Automatic => {
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
                    Some(generate_password(num))
                }
                PasswordGeneration::Manual => Some(
                    input("Enter your new password")
                        .placeholder("Choose a strong password!")
                        .interact()?,
                ),
                PasswordGeneration::NoPassword => None,
            };
            password.map(|password| {
                insert_data(
                    &connection,
                    &name,
                    &master,
                    PasswordField::Password,
                    &password,
                )
            });
        }
        Operation::Read => {
            let name: String = input("Enter Password name?")
                .placeholder("My new password")
                .required(true)
                .interact()?;
            let res = read_password(&connection, &name, &master)?;
            let str = res.map_or_else(
                || String::from("No password was found with that name."),
                |password_info: PasswordInfo| {
                    let fields = [
                        password_info.email,
                        password_info.username,
                        password_info.password,
                        password_info.notes,
                    ];
                    fields
                        .iter()
                        .enumerate()
                        .map(|(index, field)| {
                            let field_name = match index {
                                0 => "email",
                                1 => "username",
                                2 => "password",
                                3 => "notes",
                                _ => "",
                            };
                            field.as_ref().map_or_else(
                                || format!("No data found for {}", field_name),
                                |f| format!("{}: {}", field_name, f),
                            )
                        })
                        .collect::<Vec<String>>()
                        .join("\n")
                },
            );
            note("Password Info", str)?;
        }
        Operation::Delete => {}
        Operation::Exit => {}
    }
    outro("You're all set!")?;
    Ok(())
}

pub fn confirmed_password() -> Result<String, io::Error> {
    let new_password: String = password("Enter new password").mask('*').interact()?;

    let confirm: String = password("Confirm new password")
        .mask('*')
        .validate(move |pass: &String| {
            if pass != &new_password {
                Err("Passwords must match")
            } else {
                Ok(())
            }
        })
        .interact()?;
    Ok(confirm)
}

#[derive(Default, Clone, PartialEq, Eq)]
enum Operation {
    CreateOrUpdate,
    Read,
    Delete,
    #[default]
    Exit,
}

#[derive(Default, Clone, PartialEq, Eq)]
enum PasswordGeneration {
    #[default]
    Automatic,
    Manual,
    NoPassword,
}

pub fn prompt_field(
    connection: &Connection,
    master: &str,
    name: &str,
    param: PasswordField,
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
