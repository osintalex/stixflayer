use extism_pdk::*;
use serde_json::Value;
use stixflayer::DomainObjectBuilder;

#[plugin_fn]
pub fn attack_pattern(input: String) -> FnResult<String> {
    let input: Value = serde_json::from_str(&input).map_err(|e| Error::new(e))?;

    let mut builder = DomainObjectBuilder::new("attack-pattern").map_err(|e| Error::new(e))?;

    if let Some(name) = input.get("name").and_then(|v| v.as_str()) {
        builder = builder.name(name.to_string()).map_err(|e| Error::new(e))?;
    }
    if let Some(desc) = input.get("description").and_then(|v| v.as_str()) {
        builder = builder
            .description(desc.to_string())
            .map_err(|e| Error::new(e))?;
    }
    if let Some(aliases) = input.get("aliases").and_then(|v| v.as_array()) {
        let alias_vec: Vec<String> = aliases
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        builder = builder.aliases(alias_vec).map_err(|e| Error::new(e))?;
    }

    let domain_object = builder.build().map_err(|e| Error::new(e))?;

    let json = serde_json::to_string(&domain_object).map_err(|e| Error::new(e))?;

    Ok(json.into())
}
