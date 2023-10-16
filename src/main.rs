use cliclack::{input, log, multiselect, password, select};

use crate::db_ops::*;

mod crypto;
mod db_ops;
mod error;
mod password;

fn main() {
    use cliclack::{intro, outro};

    let connection = establish_connection().unwrap();
    create_table(&connection).unwrap();

    intro("passman").unwrap();
    if !check_master(&connection).unwrap() {
        log::error("master does not exist!").unwrap();
        return;
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
}
