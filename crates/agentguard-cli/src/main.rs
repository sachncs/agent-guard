use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(name = "agentguard", version, about = "Cedar-powered authorization for AI agents", long_about = None)]
struct Cli {
    /// Path to policy store (default: .agentguard)
    #[arg(long, global = true, default_value = ".agentguard")]
    store: String,

    /// Path to decision log (default: .audit/decisions.jsonl)
    #[arg(long, global = true, default_value = ".audit/decisions.jsonl")]
    audit: String,

    /// Output format (json|pretty)
    #[arg(long, global = true, default_value = "pretty")]
    output: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Initialize a new agentguard store in the current directory.
    Init {
        /// Project name (used as default org in policies)
        #[arg(long, default_value = "myorg")]
        name: String,
    },
    /// Validate policies against the schema.
    Validate,
    /// Run a single authorization check from a request file or stdin.
    Authorize {
        /// Path to a JSON request, or '-' for stdin
        #[arg(default_value = "-")]
        request: String,
        /// Path to entities.json (default: .agentguard/entities.json)
        #[arg(long)]
        entities: Option<String>,
        /// Skip the audit log for this decision
        #[arg(long)]
        no_audit: bool,
    },
    /// Simulate: same as authorize, but always reads from a file and pretty-prints.
    Sim {
        #[arg(default_value = "-")]
        request: String,
        #[arg(long)]
        entities: Option<String>,
    },
    /// Mint a delegation token.
    Delegate {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        actions: Vec<String>,
        #[arg(long)]
        resources: Vec<String>,
        #[arg(long, default_value_t = 900)]
        ttl: i64,
        #[arg(long)]
        key_id: Option<String>,
        #[arg(long)]
        key_file: Option<String>,
        /// Write token to this file instead of stdout
        #[arg(long)]
        out: Option<String>,
    },
    /// Verify and inspect a delegation token.
    Verify {
        /// Compact token string, or path to a file with the token on a single line
        token: String,
        /// Public key file (one or more key_id=base64 lines)
        #[arg(long)]
        keys: String,
    },
    /// Inspect the schema.
    Schema,
    /// Tail/query the audit log.
    Log {
        #[command(subcommand)]
        action: LogCmd,
    },
    /// Generate Cedar policy from a natural language description (requires --api-key or OPENAI_API_KEY env).
    Gen {
        description: String,
        /// Write generated policy to this file under policies/
        #[arg(long)]
        name: Option<String>,
        /// LLM provider (openai|anthropic)
        #[arg(long, default_value = "openai")]
        provider: String,
        /// Model name
        #[arg(long, default_value = "gpt-4o-mini")]
        model: String,
    },
}

#[derive(Subcommand)]
enum LogCmd {
    /// Show last N entries (default 20).
    Tail {
        #[arg(long, default_value_t = 20)]
        n: usize,
        /// Filter by principal
        #[arg(long)]
        principal: Option<String>,
        /// Filter by action substring
        #[arg(long)]
        action: Option<String>,
    },
    /// Pretty-print all entries (use sparingly).
    Dump,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,agentguard=info")),
        )
        .init();

    let cli = Cli::parse();
    let out = cli.output.as_str();

    let res: anyhow::Result<()> = match cli.cmd {
        Cmd::Init { name } => commands::init::run(&cli.store, &name),
        Cmd::Validate => commands::validate::run(&cli.store, out),
        Cmd::Authorize {
            request,
            entities,
            no_audit,
        } => {
            commands::authorize::run(
                &cli.store,
                &cli.audit,
                &request,
                entities.as_deref(),
                no_audit,
                out,
            )
            .await
        }
        Cmd::Sim { request, entities } => {
            commands::sim::run(&cli.store, &request, entities.as_deref(), out)
        }
        Cmd::Delegate {
            from,
            to,
            actions,
            resources,
            ttl,
            key_id,
            key_file,
            out: out_path,
        } => commands::delegate::run(
            &from,
            &to,
            actions,
            resources,
            ttl,
            key_id.as_deref(),
            key_file.as_deref(),
            out_path.as_deref(),
            out,
        ),
        Cmd::Verify { token, keys } => commands::delegate::verify(&token, &keys, out),
        Cmd::Schema => commands::schema::run(&cli.store, out),
        Cmd::Log { action } => match action {
            LogCmd::Tail {
                n,
                principal,
                action,
            } => commands::log::tail(&cli.audit, n, principal.as_deref(), action.as_deref(), out),
            LogCmd::Dump => commands::log::dump(&cli.audit, out),
        },
        Cmd::Gen {
            description,
            name,
            provider,
            model,
        } => {
            commands::gen::run(
                &cli.store,
                &description,
                name.as_deref(),
                &provider,
                &model,
                out,
            )
            .await
        }
    };

    res
}
