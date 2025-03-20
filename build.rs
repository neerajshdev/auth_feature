use std::{env, error::Error, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .file_descriptor_set_path(out_dir.join("auth_protobuf_descriptor.bin"))
        .compile_protos(
            &[
                "auth_protobuf_scheme/auth/protobuf/auth_service.proto",
            ],
            &["auth_protobuf_scheme"],
        )?;

    Ok(())
}
