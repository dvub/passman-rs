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
    error::BackendError,
    password::PasswordField,
};
use clap::Parser;
use cli::{interactive, util::print_password_info};

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
            [email, username, notes, password]
                .iter()
                .enumerate()
                .for_each(|(index, field)| {
                    if let Some(data) = field {
                        let column_name = match index {
                            0 => PasswordField::Email,
                            1 => PasswordField::Username,
                            2 => PasswordField::Notes,
                            3 => PasswordField::Password,
                            _ => {}
                        };
                        let _ = insert_data(&connection, &name, &master, column_name, data);
                    }
                });
        }
        PasswordCommands::Get { name } => {
            let password = read_password(&connection, &name, &master)?;
            if let Some(p) = password {
                print_password_info(p);
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
