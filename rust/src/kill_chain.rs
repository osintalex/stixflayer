//! Kill-chain phases for STIX objects.
use crate::error::{CheckContext, Entry, StixError as Error};
use serde::{Deserialize, Serialize};

/// Represents a phase in a kill-chain, i.e. one of the phases an attacker may undertake to achieve their objective.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_i4tjv75ce50h>
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillChainPhase {
    /// The name of the kill chain.
    /// This should be all lowercase and should use hyphens instead of spaces or underscores as word separators.
    kill_chain_name: String,
    /// The name of the phase in the kill chain.
    /// This should be all lowercase and should use hyphens instead of spaces or underscores as word separators.
    phase_name: String,
}

impl KillChainPhase {
    /// Creates a new kill-chain phase
    /// When referencing the Lockcheed Martin Cyber Kill Chain, the kill_chain field must be "lockheed-martin-cyber-kill-chain"
    pub fn new(kill_chain: &str, phase: &str) -> Self {
        Self {
            kill_chain_name: kill_chain.to_string(),
            phase_name: phase.to_string(),
        }
    }
}

impl crate::base::Stix for KillChainPhase {
    fn check(&self, ctx: &mut CheckContext) -> Result<(), Error> {
        fn validate_string(ctx: &mut CheckContext, kcp_string: &str, string_label: &str) {
            let valid = !kcp_string.contains(' ')
                && !kcp_string.contains('_')
                && !kcp_string.split('-').any(|word| word.is_empty())
                && kcp_string
                    .chars()
                    .all(|c| c.is_lowercase() || c.is_ascii_digit() || c == '-');
            if !valid {
                ctx.warn(
                    Entry::new(
                        "value_not_lowercase_hyphenated",
                        format!(
                            "{} {} should be lowercase and use hyphens instead of spaces or underscores as word separators.",
                            string_label, kcp_string
                        ),
                    )
                    .property(string_label)
                    .value(kcp_string),
                );
            }
        }

        validate_string(ctx, &self.kill_chain_name, "kill_chain_name");
        validate_string(ctx, &self.phase_name, "phase_name");

        Ok(())
    }
}
