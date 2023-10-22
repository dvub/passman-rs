mod args;
mod backend;
mod cli;

use args::PwdArgs;
use backend::db_ops::util::{create_table, establish_connection};
use clap::Parser;
use cli::interactive;

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

    Ok(())
}
