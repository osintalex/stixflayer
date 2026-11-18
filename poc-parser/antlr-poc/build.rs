fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR");
    let generation = antlr_rust_codegen::Builder::new()
        .grammar("../grammar/STIXPattern.g4")
        .library_directory("../grammar")
        .out_dir(out_dir)
        .generate()?;
    generation.emit_rerun_if_changed();
    Ok(())
}
