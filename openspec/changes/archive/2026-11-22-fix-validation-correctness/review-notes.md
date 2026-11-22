# Review Notes

## Manual validation of public feeds (task 6.3)

The feeds are not vendored. They were downloaded to `/tmp` and parsed with the
Rust `Bundle::from_json_outcome` API using a throwaway example
(`rust/examples/validate_feeds.rs`, removed after the check):

```rust
use std::env;
use stixflayer::bundles::Bundle;

fn main() {
    for path in env::args().skip(1) {
        let json = std::fs::read_to_string(&path).expect("read feed");
        let outcome = Bundle::from_json_outcome(&json);
        println!(
            "{path}: valid={} errors={} warnings={}",
            outcome.valid,
            outcome.errors.len(),
            outcome.warnings.len()
        );
        for entry in &outcome.errors {
            println!("  error: {} | {}", entry.kind, entry.message);
        }
        for entry in &outcome.warnings {
            println!("  warning: {} | {}", entry.kind, entry.message);
        }
    }
}
```

Commands:

```bash
curl -sSL https://raw.githubusercontent.com/AmnestyTech/investigations/master/2023-03-29_android_campaign/malware.stix2 -o /tmp/amnesty.stix2
curl -sSL https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/cellebrite/cellebrite.stix2 -o /tmp/mvt.stix2
cd rust && cargo run --quiet --example validate_feeds -- /tmp/amnesty.stix2 /tmp/mvt.stix2
```

Results:

```text
/tmp/amnesty.stix2: valid=true errors=0 warnings=0
/tmp/mvt.stix2: valid=true errors=0 warnings=1
  warning: identifier_uuid_not_v4 | STIX objects other than SCOs SHOULD use UUIDv4 identifiers; 'relationship--de7d55fe-a2d5-5352-9828-7a6843175aca' uses UUIDv5
```

- Amnesty (`malware.stix2`, 4,375 objects): zero errors, zero warnings.
- MVT (`cellebrite.stix2`, 3 objects): zero errors, exactly one identifier
  warning (`identifier_uuid_not_v4`).
