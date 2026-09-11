fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os("PROTOC").is_none() {
        let candidates = [
            "protoc",
            // Common install paths on macOS (Homebrew) and Linux so
            // the build script can give a helpful error instead of
            // "protoc: command not found".
            "/opt/homebrew/bin/protoc",
            "/usr/local/bin/protoc",
            "/usr/bin/protoc",
        ];
        if !candidates.iter().any(|c| std::path::Path::new(c).exists()) {
            return Err(format!(
                "protoc not found on PATH; install protobuf-compiler \
                 (apt: 'apt install -y protobuf-compiler', brew: 'brew install protobuf') \
                 or set $PROTOC to its path"
            )
            .into());
        }
    }
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/agentguard.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/agentguard.proto");
    Ok(())
}
