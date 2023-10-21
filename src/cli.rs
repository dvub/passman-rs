use crate::backend::{
    crypto::{generate_password, hash},
    db_ops::{
        authenticate, check_password_exists, delete_password, get_password, insert_data,
        read_password, MASTER_KEYWORD,
    },
    password::{PasswordField, PasswordInfo},
};
use cliclack::{confirm, input, note, outro, password, select};
use colored::Colorize;
use rusqlite::Connection;
use std::io;

// simple and probably unnecessary enums for control flow in the main application

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

#[derive(Default, Clone, PartialEq, Eq)]
pub enum LoginOperations {
    Login,
    Reset,
    #[default]
    Exit,
}
// these are the CLI frontend implementations of the CRUD operations

/// Series of prompts to insert a new password into the SQLite table `PasswordInfo`.
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

/// Series of prompts to read password info. If it finds data given user input, it will print the details of the given password.
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
/// Series of prompts *and **confirmations*** to delete data from the SQLite table `PasswordInfo`. Only requires an `sqlite::Connection`.
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
    // it's a big deal to delete data so make sure the user understands they're doing some serious shit
    note(
        "Password Deletion",
        "You are about to delete a password. This action is UNDOABLE and your data will be lost FOREVER. There is NO BACKUP or restoration process, so PLEASE SAVE THIS DATA BEFORE YOU DELETE IT. ",
    )?;
    let confirm = confirm("Deleting a password... Continue?")
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

// all of this is just utility functions and refactoring (and abstracting and the like)

/// Inserts a new master password given a series of prompts and inputs.
/// The input is a `confirmed_password`, meaning the user must type the same password twice.
/// The function then hashes the master password and inserts it into the SQLite table `PasswordInfo`.
/// On that note, the master password is stored in the same table as all other data, with a special keyword.
pub fn insert_master(connection: &Connection) -> anyhow::Result<()> {
    cliclack::note(
        "No master record found.",
        "You'll be prompted to create a master record by entering a new master password.",
    )?;
    let new_master = confirmed_password()?;

    note("Recovery Phrase", "This is the ONLY WAY to change your master password, so DO NOT lose this phrase.\nBetter yet, don't lose your master password.")?;
    let recovery_note: String = input("Enter a recovery phrase.").interact()?;

    let master_password = hex::encode(hash(new_master.as_bytes()));
    let note = hex::encode(hash(recovery_note.as_bytes()));

    connection.execute(
        "insert into PasswordInfo (name, password, notes) values (?1, ?2, ?3)",
        [MASTER_KEYWORD, &master_password, &note],
    )?;
    outro(format!(
        "Successfully inserted a new master record!\n\t{}",
        "Exiting...".green().bold()
    ))?;

    Ok(())
}

pub fn login(connection: &Connection) -> anyhow::Result<String> {
    let login_operation: LoginOperations = select("Select a login option.")
        .item(LoginOperations::Login, "Log in", "")
        .item(
            LoginOperations::Reset,
            "Reset master password",
            "use recovery phrase",
        )
        .item(LoginOperations::Exit, "Exit", "")
        .interact()?;

    let master = match login_operation {
        LoginOperations::Login => {
            let master = password(format!("Enter {}", "master password:".bright_red().bold()))
                .mask('*')
                .interact()?;
            if !(authenticate(&connection, &master, PasswordField::Password)?) {
                outro("Incorrect password. Exiting...".red().bold())?;
                std::process::exit(1);
            }

            master
        }
        LoginOperations::Reset => {
            let recovery_phrase =
                password(format!("Enter {}", "recovery phrase:".bright_red().bold()))
                    .mask('*')
                    .interact()?;
            if !(authenticate(&connection, &recovery_phrase, PasswordField::Notes)?) {
                outro("Incorrect recovery phrase. Exiting...".red().bold())?;
                std::process::exit(1);
            }

            let new_master = hex::encode(hash(confirmed_password()?.as_bytes()));
            connection.execute(
                "update PasswordInfo set password = ?1 where name = ?2",
                [&new_master, MASTER_KEYWORD],
            )?;

            outro("Updated master password!")?;

            std::process::exit(1);
        }
        LoginOperations::Exit => {
            outro("Exiting...".green().bold())?;
            std::process::exit(1);
        }
    };
    Ok(master)
}

/// Prompts the user for a confirmed password, meaning that they must type the same password twice.
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
/// Utility function to print the details on the availability/use of a password name when inserting/updating a password.
/// If a password exists with a given `name`, the user has the option to exit the program and not update the data.
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

/// Prompts a series of inputs to generate a password.
///  A user may either automatically generate a password or manually type one, or not insert a password at all.
///
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
/// Prints a `cliclack::note()` containing the individual fields of password data, i.e. an instance of `PasswordInfo`.
/// If no data is found, a specific message will be printed.
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
