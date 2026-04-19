use napi::Error as NapiError;
use napi_derive::napi;
use stixflayer::domain_objects::sdo::DomainObjectBuilder;
use stixflayer::error::StixError;
use stixflayer::object::StixObject;

#[napi]
pub fn version() -> String {
    "0.1.0".to_string()
}

#[napi]
pub fn test_stix() -> String {
    "STIX 2.1".to_string()
}

#[napi]
pub struct AttackPattern {
    builder: DomainObjectBuilder,
}

#[napi]
impl AttackPattern {
    #[napi(constructor)]
    pub fn new(name: String) -> Result<AttackPattern, NapiError> {
        let builder = DomainObjectBuilder::new("attack-pattern")
            .map_err(|e: StixError| NapiError::from_reason(e.to_string()))?
            .name(name)
            .map_err(|e: StixError| NapiError::from_reason(e.to_string()))?;
        Ok(AttackPattern { builder })
    }

    #[napi]
    pub fn to_json(&self) -> String {
        if let Ok(obj) = self.builder.clone().build() {
            serde_json::to_string(&StixObject::Sdo(obj)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[napi]
    pub fn get_type(&self) -> String {
        "attack-pattern".to_string()
    }
}
