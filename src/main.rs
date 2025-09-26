use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::Context;
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use clap::{Parser, Subcommand};
use pass_wall::Config;
use rand::{TryRngCore, rngs::OsRng};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about = "Password-protected proxy authentication that actually works", long_about = None)]
struct Cli {
    #[command(subcommand)]
    commands: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(about = "Start proxy authentication HTTP server.")]
    Serve {
        #[arg(short, long, default_value = "passwall.yaml")]
        config: PathBuf,
    },

    #[command(
        about = "Generate a default configuration.",
        long_about = "The default configuration will use secure defaults and generate a new key for you. However, you are still responsible for adding users and authorized hosts in the configuration file."
    )]
    Generate {
        #[arg(
            short,
            long,
            help = "Save configuration in the given path. Panics if given path already exists."
        )]
        out: PathBuf,
    },
    #[command(
        about = "Compute password hash.",
        long_about = "Use computed hash in the configuration file."
    )]
    Hash {
        #[arg(
            short,
            long,
            help = "Optional password. Read from the terminal if not provided."
        )]
        pass: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt()
        .event_format(
            tracing_subscriber::fmt::format()
                .with_line_number(true)
                .compact(),
        )
        .with_env_filter(EnvFilter::from_default_env().add_directive(LevelFilter::INFO.into()))
        .init();

    let cli = Cli::parse();
    match cli.commands.unwrap_or(Commands::Serve {
        config: Path::new("./passwall.yaml").to_path_buf(),
    }) {
        Commands::Serve { config } => serve(config).await?,
        Commands::Generate { out } => {
            let config = Config::default();
            let contents = serde_yaml_ng::to_string(&config)?;
            std::fs::write(out, contents)?;
        }
        Commands::Hash { pass } => {
            let password = match pass {
                Some(p) => p,
                None => rpassword::prompt_password("Password: ")?,
            };

            let mut salt = vec![0; argon2::RECOMMENDED_SALT_LEN];
            OsRng.try_fill_bytes(&mut salt)?;
            let salt_string = SaltString::encode_b64(&salt).map_err(|err| {
                tracing::error!(?err);
                return anyhow::anyhow!("failed to generate salt string");
            })?;

            let hash = Argon2::default()
                .hash_password(password.as_bytes(), &salt_string)
                .map_err(|err| {
                    tracing::error!(?err);
                    return anyhow::anyhow!("failed to hash password");
                })?;
            println!("{}", hash);
        }
    }

    Ok(())
}

async fn serve(config_path: PathBuf) -> anyhow::Result<()> {
    let app_config: Config = serde_yaml_ng::from_slice(
        &fs::read(config_path.clone()).context(format!("open config file: {:?}", config_path))?,
    )
    .context(format!("parse yaml config: {:?}", config_path))?;

    let listener = tokio::net::TcpListener::bind(app_config.app_bind.clone())
        .await
        .context(format!("start listener on addr: {}", app_config.app_bind))?;
    tracing::info!("starting listener");

    let app = pass_wall::app(&app_config)?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix;

    let term = async {
        unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("unable to install unix TERM signal handler")
            .recv()
            .await
    };

    let int = async {
        unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("unable to install unix INT signal handler")
            .recv()
            .await
    };

    let mut which_signal = "SIGTERM";
    tokio::select! {
        _ = int => {
            which_signal = "SIGINT";
        }
        _ = term => {},
    };

    tracing::info!("received signal {which_signal}, exiting");
}
