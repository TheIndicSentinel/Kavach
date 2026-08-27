fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo::rustc-check-cfg=cfg(console_embedded)");
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);

    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let proto_dir = manifest_dir.join("../../proto");
    let proto_file = proto_dir.join("evaluate.proto");

    println!("cargo:rerun-if-changed={}", proto_file.display());

    let console_dist = manifest_dir.join("../../console/dist");
    let console_index = console_dist.join("index.html");
    println!("cargo:rerun-if-changed={}", console_index.display());
    if console_index.is_file() {
        println!("cargo:rustc-cfg=console_embedded");
        if let Ok(entries) = std::fs::read_dir(&console_dist) {
            for entry in entries.flatten() {
                println!("cargo:rerun-if-changed={}", entry.path().display());
            }
        }
    } else {
        println!(
            "cargo:warning=console/dist missing; static console disabled. Run scripts/build-console.sh"
        );
    }

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &[proto_file],
            &[proto_dir, protoc_bin_vendored::include_path()?],
        )?;
    Ok(())
}
