use crate::{
    crypto::{generate_password, hash},
    db_ops::{
        check_password_exists, delete_password, get_password, insert_data, read_password,
        MASTER_KEYWORD,
    },
    password::{PasswordField, PasswordInfo},
};
use cliclack::{confirm, input, note, outro, password, select};
use colored::Colorize;
use rusqlite::Connection;
use std::io;

#[derive(Default, Clone, PartialEq, Eq)]
pub enum Operation {
    Insert,
    Read,
    Delete,
    #[default]
    Exit,
}
#[derive(Default, Clone, PartialEq, Eq)]
pub enum PasswordGeneration {
    Automatic,
    Manual,
    #[default]
    NoPassword,
}

pub fn insert_master(connection: &Connection, master_exists: bool) -> anyhow::Result<()> {
    if !master_exists {
        cliclack::note(
            "No master record found.",
            "You'll be prompted to create a master record by entering a new master password.",
        )?;
        let new_master = confirmed_password()?;

        let master_password = hex::encode(hash(new_master.as_bytes()));
        connection.execute(
            "insert into PasswordInfo (name, password) values (?1, ?2)",
            [MASTER_KEYWORD, &master_password],
        )?;
        outro(format!(
            "Successfully inserted a new master record!\n\t{}",
            "Exiting...".green().bold()
        ))?;
    }
    Ok(())
}

pub fn insert(connection: &Connection, master: &str) -> anyhow::Result<()> {
    let name: String = input("Enter Password name?")
        .placeholder("My new password")
        .required(true)
        .interact()?;
    check_password_availability(connection, &name)?;
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
    prompt_password(connection, &name, &master)?;

    outro(format!(
        "Successfully inserted a new password!\n\t{}",
        "Exiting...".green().bold()
    ))?;
    Ok(())
}
pub fn check_password_availability(connection: &Connection, name: &str) -> anyhow::Result<()> {
    if get_password(&connection, &name)?.is_some() {
        let confirm =
            confirm("A password already exists with this name. Would you like to update it?")
                .interact()?;
        if !confirm {
            return Ok(());
        }
        note(
            "Note",
            "If you do not messagewish to update a particular field, leave the value empty.",
        )?;
    } else {
        note(
            "Name is unused",
            "This name is available. Continuing will insert a new password.",
        )?;
    }
    Ok(())
}

pub fn prompt_password(connection: &Connection, name: &str, master: &str) -> anyhow::Result<()> {
    let password_type: PasswordGeneration = select("Select password generation type (optional)")
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
        PasswordGeneration::Automatic => Some(prompt_automatic()?),
        PasswordGeneration::Manual => Some(confirmed_password()?),
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
    Ok(())
}

pub fn prompt_automatic() -> Result<String, io::Error> {
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
    Ok(generate_password(num))
}

pub fn read(connection: &Connection, master: &str) -> anyhow::Result<()> {
    let name: String = input("Enter Password name?")
        .placeholder("My new password")
        .required(true)
        .interact()?;
    let res = read_password(&connection, &name, &master)?;
    let str = res.map_or_else(
        || String::from("No password was found with that name."),
        |password_info: PasswordInfo| print_password_info(password_info),
    );
    note("Password Info", str)?;
    outro("Exiting...".bold())?;
    Ok(())
}
pub fn print_password_info(password_info: PasswordInfo) -> String {
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
}

pub fn delete(connection: &Connection) -> anyhow::Result<()> {
    let name: String = input("Enter Password name?")
        .placeholder("My new password")
        .required(true)
        .interact()?;

    let check_exists = check_password_exists(&connection, &name)?;
    if !check_exists {
        outro("No password found with that name.")?;
        return Ok(());
    }
    let confirm = confirm("you are about to delete a password. Continue?")
        .initial_value(false)
        .interact()?;

    if !confirm {
        outro("Exiting...")?;
        return Ok(());
    }

    delete_password(&connection, &name)?;
    outro("Successfully deleted password.".bold())?;
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
