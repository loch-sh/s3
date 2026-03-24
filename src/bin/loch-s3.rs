use clap::{Args, Parser, Subcommand};
use reqwest::Url;
use reqwest::blocking::Client;
use reqwest::header::AUTHORIZATION;

#[derive(Parser)]
#[command(
    name = "loch-s3",
    about = "CLI for the Loch S3 user management API",
    version
)]
struct Cli {
    /// Server URL
    #[arg(
        long,
        global = true,
        default_value = "http://localhost:8080",
        env = "LOCH_SERVER"
    )]
    server: String,

    /// Admin API key (Bearer token). Prefer LOCH_ADMIN_KEY env var over the flag to avoid
    /// exposing the secret in the process list.
    // Note: clap 4 does not allow global + required, so we validate manually in main().
    #[arg(long = "api-key", global = true, env = "LOCH_ADMIN_KEY")]
    api_key: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// User management
    Users(UsersArgs),
}

#[derive(Args)]
struct UsersArgs {
    #[command(subcommand)]
    command: UsersCmd,
}

#[derive(Subcommand)]
enum UsersCmd {
    /// List all users
    List,
    /// Get a specific user
    Get { user_id: String },
    /// Create or update a user.
    /// Prefer LOCH_ACCESS_KEY / LOCH_SECRET_KEY env vars to avoid exposing secrets in the
    /// process list.
    Put {
        user_id: String,
        #[arg(long)]
        display_name: String,
        #[arg(long, env = "LOCH_ACCESS_KEY")]
        access_key: String,
        #[arg(long, env = "LOCH_SECRET_KEY")]
        secret_key: String,
    },
    /// Delete a user
    Delete { user_id: String },
}

fn users_url(server: &str, user_id: Option<&str>) -> Url {
    let mut url = Url::parse(server).unwrap_or_else(|e| {
        eprintln!("Invalid server URL '{}': {}", server, e);
        std::process::exit(1);
    });
    {
        let mut segments = url.path_segments_mut().unwrap_or_else(|_| {
            eprintln!("Invalid server URL: cannot be a cannot-be-a-base URL");
            std::process::exit(1);
        });
        segments.extend(["_loch", "users"]);
        if let Some(uid) = user_id {
            segments.push(uid);
        }
    }
    url
}

fn bearer(api_key: &str) -> String {
    format!("Bearer {}", api_key)
}

fn send_or_exit(req: reqwest::blocking::RequestBuilder) -> reqwest::blocking::Response {
    req.send().unwrap_or_else(|e| {
        eprintln!("Request failed: {}", e);
        std::process::exit(1);
    })
}

fn print_error_and_exit(resp: reqwest::blocking::Response) -> ! {
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    eprintln!("Error {}: {}", status, body);
    std::process::exit(1);
}

fn print_json(resp: reqwest::blocking::Response) {
    let value: serde_json::Value = resp.json().unwrap_or_else(|e| {
        eprintln!("Failed to parse response: {}", e);
        std::process::exit(1);
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&value).expect("Value is always serializable")
    );
}

fn cmd_users_list(client: &Client, server: &str, api_key: &str) {
    let url = users_url(server, None);
    let resp = send_or_exit(client.get(url).header(AUTHORIZATION, bearer(api_key)));

    if !resp.status().is_success() {
        print_error_and_exit(resp);
    }
    print_json(resp);
}

fn cmd_users_get(client: &Client, server: &str, api_key: &str, user_id: &str) {
    let url = users_url(server, Some(user_id));
    let resp = send_or_exit(client.get(url).header(AUTHORIZATION, bearer(api_key)));

    if !resp.status().is_success() {
        print_error_and_exit(resp);
    }
    print_json(resp);
}

fn cmd_users_put(
    client: &Client,
    server: &str,
    api_key: &str,
    user_id: &str,
    display_name: &str,
    access_key: &str,
    secret_key: &str,
) {
    let url = users_url(server, Some(user_id));
    let body = serde_json::json!({
        "display_name": display_name,
        "access_key_id": access_key,
        "secret_access_key": secret_key,
    });
    let resp = send_or_exit(
        client
            .put(url)
            .header(AUTHORIZATION, bearer(api_key))
            .json(&body),
    );

    let status = resp.status();
    if !status.is_success() {
        print_error_and_exit(resp);
    }
    if status == reqwest::StatusCode::CREATED {
        println!("Created");
    } else {
        println!("Updated");
    }
}

fn cmd_users_delete(client: &Client, server: &str, api_key: &str, user_id: &str) {
    let url = users_url(server, Some(user_id));
    let resp = send_or_exit(client.delete(url).header(AUTHORIZATION, bearer(api_key)));

    if !resp.status().is_success() {
        print_error_and_exit(resp);
    }
    println!("Deleted");
}

fn main() {
    let cli = Cli::parse();
    let api_key = cli.api_key.unwrap_or_else(|| {
        eprintln!("error: --api-key or LOCH_ADMIN_KEY is required");
        std::process::exit(1);
    });
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("failed to build HTTP client");

    match cli.command {
        Commands::Users(args) => match args.command {
            UsersCmd::List => cmd_users_list(&client, &cli.server, &api_key),
            UsersCmd::Get { user_id } => cmd_users_get(&client, &cli.server, &api_key, &user_id),
            UsersCmd::Put {
                user_id,
                display_name,
                access_key,
                secret_key,
            } => cmd_users_put(
                &client,
                &cli.server,
                &api_key,
                &user_id,
                &display_name,
                &access_key,
                &secret_key,
            ),
            UsersCmd::Delete { user_id } => {
                cmd_users_delete(&client, &cli.server, &api_key, &user_id)
            }
        },
    }
}
