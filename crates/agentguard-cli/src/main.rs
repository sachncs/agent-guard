use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(name = "agentguard", version, about = "Cedar-powered authorization for AI agents", long_about = None)]
struct Cli {
    /// Path to policy store (default: .agentguard, or $AGENTGUARD_STORE)
    #[arg(
        long,
        global = true,
        env = "AGENTGUARD_STORE",
        default_value = ".agentguard"
    )]
    store: String,

    /// Path to decision log (default: .audit/decisions.jsonl, or $AGENTGUARD_AUDIT)
    #[arg(
        long,
        global = true,
        env = "AGENTGUARD_AUDIT",
        default_value = ".audit/decisions.jsonl"
    )]
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
    /// Audit log operations (verify, export, SAR, erase, notarize).
    Audit {
        #[command(subcommand)]
        action: AuditCmd,
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
    /// Diagnose a deployment: schema, policies, audit log, chain, authorizer.
    Doctor,
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

#[derive(Subcommand)]
enum AuditCmd {
    /// Walk the HMAC chain and verify every record.
    Verify {
        /// Path to the audit log (default: --audit)
        #[arg(long)]
        audit: Option<String>,
        /// Path to the secret file containing the HMAC root key
        #[arg(long)]
        secret_file: String,
    },
    /// Re-format the audit log for SIEM ingestion.
    Export {
        /// Path to the audit log (default: --audit)
        #[arg(long)]
        audit: Option<String>,
        /// Output format: jsonl | cef | leef | ecs
        #[arg(long, default_value = "ecs")]
        format: String,
        /// Output path (default: stdout)
        #[arg(long)]
        out: Option<String>,
    },
    /// Subject access report — find all decisions about a data subject.
    Sar {
        /// Path to the audit log (default: --audit)
        #[arg(long)]
        audit: Option<String>,
        /// Subject ID (principal) to search for
        subject_id: String,
    },
    /// Pseudonymize a subject's records (GDPR Art. 17 erasure).
    Erase {
        /// Path to the audit log (default: --audit)
        #[arg(long)]
        audit: Option<String>,
        /// Subject ID to erase
        subject_id: String,
        /// Salt file (random bytes) — required to ensure irreversibility
        #[arg(long)]
        salt_file: String,
        /// Output path for the pseudonymized log (default: overwrite input)
        #[arg(long)]
        out: Option<String>,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let exit_code = run().await;
    // std::process::exit runs after all Drop, including the tracing
    // subscriber. This is the last thing the program does.
    std::process::exit(exit_code);
}

async fn run() -> i32 {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,agentguard=info")),
        )
        .init();

    let cli = Cli::parse();
    let out = cli.output.as_str();

    let mut exit_code: i32 = 0;
    let res: anyhow::Result<()> = match cli.cmd {
        Cmd::Init { name } => commands::init::run(&cli.store, &name),
        Cmd::Validate => commands::validate::run(&cli.store, out),
        Cmd::Authorize {
            request,
            entities,
            no_audit,
        } => {
            let outcome = match commands::authorize::run(
                &cli.store,
                &cli.audit,
                &request,
                entities.as_deref(),
                no_audit,
                out,
            )
            .await
            {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("error: {e:?}");
                    return 1;
                }
            };
            // Translate a Deny into an exit code at the end of `main`, after
            // all Drop runs. This avoids `std::process::exit` skipping
            // destructors inside the authorize command.
            if !outcome.decision_was_allow {
                exit_code = 2;
            }
            Ok::<(), anyhow::Error>(())
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
        Cmd::Audit { action } => match action {
            AuditCmd::Verify { audit, secret_file } => {
                let path = audit.as_deref().unwrap_or(&cli.audit);
                commands::audit::verify(path, &secret_file, out)
            }
            AuditCmd::Export {
                audit,
                format,
                out: out_path,
            } => {
                let path = audit.as_deref().unwrap_or(&cli.audit);
                commands::audit::export(path, &format, out_path.as_deref(), out)
            }
            AuditCmd::Sar { audit, subject_id } => {
                let path = audit.as_deref().unwrap_or(&cli.audit);
                commands::audit::sar(path, &subject_id, out)
            }
            AuditCmd::Erase {
                audit,
                subject_id,
                salt_file,
                out: out_path,
            } => {
                let path = audit.as_deref().unwrap_or(&cli.audit);
                commands::audit::erase(path, &subject_id, &salt_file, out_path.as_deref())
            }
        },
        Cmd::Doctor => {
            let chain_secret = std::env::var("AGENTGUARD_CHAIN_SECRET")
                .ok()
                .map(std::path::PathBuf::from);
            let report = match commands::doctor::run(
                std::path::Path::new(&cli.store),
                std::path::Path::new(&cli.audit),
                chain_secret.as_deref(),
            ) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("error: {e:?}");
                    return 1;
                }
            };
            report.print();
            exit_code = if report.has_failures() {
                1
            } else if report.has_warnings() {
                2
            } else {
                0
            };
            Ok::<(), anyhow::Error>(())
        }
    };

    if let Err(e) = res {
        eprintln!("error: {e:?}");
        if exit_code == 0 {
            exit_code = 1;
        }
    }
    exit_code
}
