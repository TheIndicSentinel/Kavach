// The console check, shared with the library (where it is unit-tested).
include!("src/console_build.rs");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo::rustc-check-cfg=cfg(console_embedded)");
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);

    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let proto_dir = manifest_dir.join("../../proto");
    let proto_file = proto_dir.join("evaluate.proto");

    println!("cargo:rerun-if-changed={}", proto_file.display());
    println!("cargo:rerun-if-changed=src/console_build.rs");

    // Embed the console only when dist/ holds a real build: a stub
    // index.html would be served as a blank page.
    let console_dist = manifest_dir.join("../../console/dist");
    let console_index = console_dist.join("index.html");
    println!("cargo:rerun-if-changed={}", console_index.display());
    match std::fs::read_to_string(&console_index) {
        Ok(index) => {
            // A directory is scanned whole for changes.
            println!("cargo:rerun-if-changed={}", console_dist.display());
            match not_a_build(&index, |asset| console_dist.join(asset).is_file()) {
                None => println!("cargo:rustc-cfg=console_embedded"),
                Some(why) => println!(
                    "cargo:warning=console/dist is not a console build ({why}); static console disabled. Run scripts/build-console.sh"
                ),
            }
        }
        Err(_) => println!(
            "cargo:warning=console/dist missing; static console disabled. Run scripts/build-console.sh"
        ),
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
