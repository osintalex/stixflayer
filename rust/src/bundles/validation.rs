//! Bundle-specific validation logic.

use std::collections::{HashMap, HashSet};

use crate::{
    base::Stix,
    bundles::Bundle,
    error::{add_error, return_multiple_errors, StixError as Error},
    object::StixObject,
    relationship_objects::RelationshipObjectType,
    types::Identified,
};

impl Stix for Bundle {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Bundles must be of type "bundle"
        if &self.object_type != "bundle" {
            errors.push(Error::ValidationError(format!(
                "STIX bundles must have a `type` of 'bundle'. Bundle {} has a type of {}",
                self.id, self.object_type
            )));
        }

        // Validate the id
        add_error(&mut errors, self.id.stix_check());

        // Bundles must contain at least one object
        if self.objects.is_empty() {
            errors.push(Error::ValidationError(
                "Bundle must contain at least one object".to_string(),
            ));
        }

        // Validate all contained objects and check for duplicate IDs
        let mut seen_ids: HashMap<String, Option<String>> = HashMap::new();
        for object in self.objects.iter() {
            add_error(&mut errors, object.stix_check());

            let id = object.get_id();
            let modified = object.get_modified();

            if let Some(prev_modified) = seen_ids.get(&id) {
                // Allow duplicates only if both have different `modified` timestamps
                let both_versioned =
                    prev_modified.is_some() && modified.is_some() && prev_modified != &modified;
                if !both_versioned {
                    errors.push(Error::ValidationError(format!(
                        "Bundle contains duplicate object id: {}",
                        id
                    )));
                }
            } else {
                seen_ids.insert(id, modified);
            }
        }

        // enforce-refs: check that Relationship source_ref/target_ref point to objects in the bundle
        let bundle_ids: HashSet<String> = self
            .objects
            .iter()
            .filter(|obj| obj.get_type() != "relationship")
            .map(|obj| obj.get_id())
            .collect();
        for object in self.objects.iter() {
            if let StixObject::Sro(sro) = object {
                if let RelationshipObjectType::Relationship(ref rel) = sro.object_type {
                    if !bundle_ids.contains(&rel.source_ref.to_string()) {
                        errors.push(Error::ValidationError(format!(
                            "Relationship object {} makes reference to {} which is not found in current bundle.",
                            sro.get_id(), rel.source_ref
                        )));
                    }
                    if !bundle_ids.contains(&rel.target_ref.to_string()) {
                        errors.push(Error::ValidationError(format!(
                            "Relationship object {} makes reference to {} which is not found in current bundle.",
                            sro.get_id(), rel.target_ref
                        )));
                    }
                }
            }
        }

        return_multiple_errors(errors)
    }
}
