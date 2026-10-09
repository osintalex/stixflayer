//! Allocation profile of bundle parsing.

use std::{fs, path::Path};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() {
    let _profiler = dhat::Profiler::new_heap();

    let manifest = env!("CARGO_MANIFEST_DIR");
    let bundle_path = Path::new(manifest).join("../benchmarks/data/apt1.json");
    let json = fs::read_to_string(&bundle_path).expect("failed to read apt1 bundle");

    let iterations = 2;
    for _ in 0..iterations {
        let _bundle = stixflayer::Bundle::from_json(&json).expect("bundle should parse");
    }
}
