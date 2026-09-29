//! Tool SDO
//!
//! Tools are legitimate software that can be used by threat actors to perform attacks.
//!
//! For more information, see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_z4voa9ndw8v>

use crate::{
    base::Stix,
    common::validation::validate_vocab_list,
    domain_objects::vocab::ToolType,
    error::{add_error, return_multiple_errors, StixError as Error},
    types::KillChainPhase,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Tool {
    /// The name used to identify the Tool.
    pub name: String,
    /// A description that provides more details and context about the Tool.
    pub description: Option<String>,
    /// The kind(s) of tool(s) being described.
    pub tool_types: Option<Vec<String>>,
    /// Alternative names used to identify this Tool.
    pub aliases: Option<Vec<String>>,
    /// The list of kill chain phases for which this Tool can be used.
    pub kill_chain_phases: Option<Vec<KillChainPhase>>,
    /// The version identifier associated with the Tool.
    pub tool_version: Option<String>,
}

impl Stix for Tool {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(kill_chain_phases) = &self.kill_chain_phases {
            add_error(&mut errors, kill_chain_phases.stix_check());
        }
        if let Some(tool_types) = &self.tool_types {
            tool_types.stix_check()?;
            add_error(
                &mut errors,
                validate_vocab_list::<ToolType, _>(tool_types, "tool-type-ov"),
            );
        }
        if let Some(aliases) = &self.aliases {
            add_error(&mut errors, aliases.stix_check());
        }

        return_multiple_errors(errors)
    }
}

#[cfg(test)]
mod tests {
    
    use crate::{
        domain_objects::sdo::{DomainObject, DomainObjectBuilder},
        types::KillChainPhase,
    };
    use log::warn;
    use serde_json::Value;

    fn expected_tool() -> DomainObject {
        DomainObjectBuilder::new("tool")
            .unwrap()
            .name("Network Scanner".to_string())
            .unwrap()
            .description("A tool used for scanning and identifying network assets.".to_string())
            .unwrap()
            .tool_types(vec!["credential-exploitation".to_string()])
            .unwrap()
            .aliases(vec!["NetScan".to_string(), "Asset Mapper".to_string()])
            .unwrap()
            .kill_chain_phases(vec![KillChainPhase::new(
                "mitre-attack",
                "credential-access",
            )])
            .unwrap()
            .tool_version("1.0.3".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z")
    }

    #[test]
    fn serialize_tool() {
        let tool = expected_tool();
        let result = serde_json::to_value(&tool).unwrap();

        let expected = r#"{
        "type": "tool",
        "spec_version": "2.1",
        "id": "tool--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "name": "Network Scanner",
        "aliases": ["NetScan", "Asset Mapper"],
        "tool_types": ["credential-exploitation"],
        "description": "A tool used for scanning and identifying network assets.",
        "kill_chain_phases": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "credential-access"
            }
        ],
        "tool_version": "1.0.3"
        }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();
        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn tool_invalid_kill_chain() {
        let test_vals = vec![
            "With Uppercase",
            "with_underscores",
            "with spaces",
            "double--hyphen",
            "-leading-hyphen",
            "trailing-hyphen-",
        ];

        let mut all_invalid = true;

        for val in test_vals {
            let tool = DomainObjectBuilder::new("tool")
                .unwrap()
                .name("Network Scanner".to_string())
                .unwrap()
                .description("A tool used for scanning and identifying network assets.".to_string())
                .unwrap()
                .tool_types(vec!["credential-exploitation".to_string()])
                .unwrap()
                .aliases(vec!["NetScan".to_string(), "Asset Mapper".to_string()])
                .unwrap()
                .kill_chain_phases(vec![KillChainPhase::new(val, val)])
                .unwrap()
                .tool_version("1.0.3".to_string())
                .unwrap()
                .build();
            if tool.is_ok() {
                all_invalid = false;
                warn!(
                    "Test String Value in Kill Chain '{}' should be invalid but passed",
                    val
                );
            }
        }
        assert!(
            all_invalid,
            "Not all Test String Value in Kill Chain were invalid"
        );
    }

    #[test]
    fn tool_valid_kill_chain() {
        let test_vals = vec!["all-lowercase", "no-underscores", "no-spaces-here"];

        let mut all_valid = true;

        for val in test_vals {
            let tool = DomainObjectBuilder::new("tool")
                .unwrap()
                .name("Network Scanner".to_string())
                .unwrap()
                .description("A tool used for scanning and identifying network assets.".to_string())
                .unwrap()
                .tool_types(vec!["credential-exploitation".to_string()])
                .unwrap()
                .aliases(vec!["NetScan".to_string(), "Asset Mapper".to_string()])
                .unwrap()
                .kill_chain_phases(vec![KillChainPhase::new(val, val)])
                .unwrap()
                .tool_version("1.0.3".to_string())
                .unwrap()
                .build();
            if tool.is_err() {
                all_valid = false;
                warn!(
                    "Test String Value in Kill Chain '{}' should be valid but failed",
                    val
                );
            }
        }
        assert!(all_valid, "All Test String Value in Kill Chain were valid");
    }

    #[test]
    fn deserialize_tool() {
        let json = r#"{
        "type": "tool",
        "spec_version": "2.1",
        "id": "tool--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "name": "Network Scanner",
        "aliases": ["NetScan", "Asset Mapper"],
        "tool_types": ["credential-exploitation"],
        "description": "A tool used for scanning and identifying network assets.",
        "kill_chain_phases": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "credential-access"
            }
        ],
        "tool_version": "1.0.3"
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();
        assert_eq!(result, expected_tool());
    }
}
