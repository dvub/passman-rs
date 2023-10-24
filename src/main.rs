mod args;
mod backend;
mod cli;

use args::{PasswordCommands, PasswordTypes, PwdArgs};
use backend::{
    crypto::generate_password,
    db_ops::{
        crud::{insert_data, read_password},
        util::{create_table, establish_connection},
    },
    password::PasswordField,
};
use clap::Parser;
use cli::{interactive, util::print_password_info};
use cliclack::note;

// todo
// [x] refactor monolith frontend
// [~] add nice colors to frontend

// add clap support

// SPEED
// benchmarking

fn main() -> anyhow::Result<()> {
    let connection = establish_connection()?;
    create_table(&connection)?;

    let args = PwdArgs::parse();
    if args.interactive {
        interactive(&connection)?;
        return Ok(());
    }
    if args.command.is_none() {
        println!("No command was supplied. Use -h or --help for more information.");
        return Ok(());
    }

    let command = args.command.unwrap();
    let master = args.master_password.unwrap();
    match command {
        PasswordCommands::Add {
            name,
            email,
            username,
            notes,
            password_type,
        } => {
            let password = password_type.map(|t| match t {
                PasswordTypes::Manual { password } => password,
                PasswordTypes::Auto { length } => generate_password(length),
            });

            if let Some(data) = email {
                insert_data(&connection, &name, &master, PasswordField::Email, &data)?;
            }
            if let Some(data) = username {
                insert_data(&connection, &name, &master, PasswordField::Username, &data)?;
            }
            if let Some(data) = notes {
                insert_data(&connection, &name, &master, PasswordField::Notes, &data)?;
            }
            if let Some(data) = password {
                insert_data(&connection, &name, &master, PasswordField::Password, &data)?;
            }
        }
        PasswordCommands::Get { name } => {
            let password = read_password(&connection, &name, &master)?;
            if let Some(p) = password {
                print_password_info(p);
            } else {
                note("Password Info", "No password found")?;
            }
        }
        PasswordCommands::Update {
            name,
            new_name,
            email,
            username,
            notes,
            password_type,
        } => {}
        PasswordCommands::List => {}
        PasswordCommands::Delete { name, confirm } => {}
    }

    Ok(())
}
