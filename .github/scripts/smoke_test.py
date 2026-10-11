"""Wheel smoke test: import the installed package and exercise a basic call.

Run inside an environment where a built stixflayer wheel has been installed.
Used by the release workflow's per-platform smoke jobs before publishing.
"""

import stixflayer

# Build an SDO the way the README shows, then round-trip it through JSON.
ap = stixflayer.AttackPattern(
    id="attack-pattern--d3046a90-580c-4004-8208-66915bc29830",
    name="Clear Command History",
    description="Adversaries clear or remove bash_history to hide their tracks.",
    spec_version="2.1",
)
assert ap.type == "attack-pattern"
assert ap.name == "Clear Command History"
reparsed = stixflayer.AttackPattern.from_json(ap.to_json())
assert reparsed.name == ap.name
print("smoke OK:", ap.id)
