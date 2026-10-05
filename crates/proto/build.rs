// Compile le .proto en Rust au build. Utilise un protoc vendore (aucune
// dependance systeme a installer).
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(protoc) = protoc_bin_vendored::protoc_bin_path() {
        std::env::set_var("PROTOC", protoc);
    }
    tonic_prost_build::compile_protos("proto/sentinelle.proto")?;
    Ok(())
}
