use crate::base::Stix;
use crate::types::{Identifier, StixDictionary, Timestamp};
use crate::error::{add_error, return_multiple_errors, StixError as Error};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

/// Email Message
///
/// The Email Message object represents an instance of an email message, corresponding to the internet message
/// format described in [RFC5322](http://www.rfc-editor.org/info/rfc5322) and related RFCs.
///
/// Header field values that have been encoded as described in section 2 of [RFC2047](http://www.rfc-editor.org/info/rfc2047)
/// **MUST** be decoded before inclusion in Email Message object properties. For example, this is some text **MUST** be used instead
/// of =?iso-8859-1?q?this=20is=20some=20text?=. Any characters in the encoded value which cannot be decoded into Unicode
/// SHOULD be replaced with the 'REPLACEMENT CHARACTER' (U+FFFD). If it is necessary to capture the header value as observed,
/// this can be achieved by referencing an Artifact object through the raw_email_ref property.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_grboc7sq5514>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct EmailMessage {
    //bools default to false: so is_multipart only needs to be set if true
    pub is_multipart: bool,
    pub date: Option<Timestamp>,
    pub content_type: Option<String>,
    pub from_ref: Option<Identifier>,
    pub sender_ref: Option<Identifier>,
    pub to_refs: Option<Vec<Identifier>>,
    pub cc_refs: Option<Vec<Identifier>>,
    pub bcc_refs: Option<Vec<Identifier>>,
    pub message_id: Option<String>,
    pub subject: Option<String>,
    pub recieved_lines: Option<Vec<String>>,
    pub additional_header_fields: Option<StixDictionary<Vec<String>>>,
    pub body: Option<String>,
    pub body_multipart: Option<Vec<EmailMimeCompomentType>>,
    pub raw_email_ref: Option<Identifier>,
}
impl Stix for EmailMessage {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(from_ref) = &self.from_ref {
            from_ref.stix_check()?;
            let ref_type = from_ref.get_type();
            if ref_type != "email-addr" {
                errors.push(Error::ValidationError(format!(
                    "Referenced addresss {} must be 'email-addr'.",
                    ref_type
                )));
            }
        }
        if let Some(sender_ref) = &self.sender_ref {
            sender_ref.stix_check()?;
            let ref_type = sender_ref.get_type();
            if ref_type != "email-addr" {
                errors.push(Error::ValidationError(format!(
                    "Referenced addresss {} must be 'email-addr'.",
                    ref_type
                )));
            }
        }
        if let Some(to_refs) = &self.to_refs {
            to_refs.stix_check()?;
            if !to_refs.iter().any(|x| x.get_type() == "email-addr") {
                errors.push(Error::ValidationError(
                    "Referenced addresses in to_refs must be 'email-addr'.".to_string(),
                ));
            }
        }

        if let Some(cc_refs) = &self.cc_refs {
            cc_refs.stix_check()?;
            if !cc_refs.iter().any(|x| x.get_type() == "email-addr") {
                errors.push(Error::ValidationError(
                    "Referenced addressses in cc_refs must be 'email-addr'.".to_string(),
                ));
            }
        }

        if let Some(bcc_refs) = &self.bcc_refs {
            bcc_refs.stix_check()?;
            if !bcc_refs.iter().any(|x| x.get_type() == "email-addr") {
                errors.push(Error::ValidationError(
                    "Referenced addressses in cc_refs must be 'email-addr'.".to_string(),
                ));
            }
        }
        if let Some(recieved_lines) = &self.recieved_lines {
            add_error(&mut errors, recieved_lines.stix_check());
        }
        if let Some(additional_header_fields) = &self.additional_header_fields {
            add_error(&mut errors, additional_header_fields.stix_check());
        }

        if self.body.is_some() && self.is_multipart {
            errors.push(Error::ValidationError(
                "The property body MUST NOT be used if is_multipart is true".to_string(),
            ));
        }

        if let Some(ref body_multipart) = self.body_multipart {
            if !self.is_multipart {
                body_multipart.stix_check()?; // Assuming stix_check() is a method on the type of body_multipart
                errors.push(Error::ValidationError(
                    "The property body_multipart MUST NOT be used if is_multipart is false"
                        .to_string(),
                ));
            }
        }

        if let Some(raw_email_ref) = &self.raw_email_ref {
            raw_email_ref.stix_check()?;
            let ref_type = raw_email_ref.get_type();
            if ref_type != "artifact" {
                errors.push(Error::ValidationError(
                    "Raw_email_ref must be an Identifier of type artifact".to_string(),
                ));
            }
        }

        return_multiple_errors(errors)
    }
}

/// Specifies one component of a multi-part email body.
///
/// One of `body` OR `body_raw_ref` MUST be included.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailMimeCompomentType {
    /// Specifies the contents of the MIME part if the content_type is not provided or starts with `text/` (e.g., in the case of plain text or HTML email).
    pub body: Option<String>,
    /// Specifies the contents of non-textual MIME parts, that is those whose content_type does not start with `text/`, as a reference to an `Artifact` object or `File` object.
    ///
    /// The object referenced in this property **MUST** be of type `artifact` or `file`.
    /// For use cases where conveying the actual data contained in the MIME part is of primary importance, `artifact` **SHOULD** be used.
    /// Otherwise, for use cases where conveying metadata about the file-like properties of the MIME part is of primary importance, `file` **SHOULD** be used.
    pub body_raw_ref: Option<Identifier>,
    /// Specifies the value of the "Content-Type" header field of the MIME part.
    ///
    /// Any additional "Content-Type" header field parameters such as `charset` **SHOULD** be included in this property.
    pub content_type: Option<String>,
    /// Specifies the value of the "Content-Disposition" header field of the MIME part.
    pub content_disposition: Option<String>,
}

impl Stix for EmailMimeCompomentType {
    fn stix_check(&self) -> Result<(), Error> {
        if self.body.is_none() == self.body_raw_ref.is_none() {
            return Err(Error::ValidationError(
                "An email MIME component type must include either a body or a body_raw_ref"
                    .to_string(),
            ));
        } else if let Some(body_raw_ref) = &self.body_raw_ref {
            body_raw_ref.stix_check()?;
            if body_raw_ref.get_type() != "artifact" && body_raw_ref.get_type() != "file" {
                return Err(Error::ValidationError(format!("An email MIME component type's `body_raw_ref` must refer to either an artifact or a file. This refers to an object of type {}", body_raw_ref.get_type())));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(unused_imports)]
    use crate::cyber_observable_objects::sco::{CyberObject, CyberObjectBuilder};
    use crate::extensions::{
        ArchiveExtension, FileExtensions, HttpRequestExtension, IcmpExtension,
        NetworkTrafficExtensions, ProcessExtensions, SocketExtenion, SpecialExtensions,
        UnixAccountExtension, UserAccountExtensions, WindowsProcessExtension,
    };
    use crate::types::{DictionaryValue, Hashes, Identifier, StixDictionary, Timestamp};
    use log::warn;
    use serde_json::Value;
    use std::{collections::HashMap, str::FromStr};
    use test_log::test;
    use super::EmailMimeCompomentType;

    #[test]
    fn deserialize_emailmessage() {
        let json = r#"{
            "type": "email-message",
            "spec_version": "2.1",
            "id": "email-message--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "from_ref": "email-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "to_refs": ["email-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5"],
            "is_multipart": false,
            "date": "1997-11-21T15:55:06Z",
            "subject": "Saying Hello"
        }"#;
        let result = CyberObject::from_json(json, false).unwrap();
        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .from_ref(Identifier::new_test("email-addr"))
            .unwrap()
            .to_refs([Identifier::new_test("email-addr")].to_vec())
            .unwrap()
            .date(Timestamp("1997-11-21T15:55:06Z".parse().unwrap()))
            .unwrap()
            .subject("Saying Hello".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();
        assert_eq!(result, email_message)
    }

    #[test]
    fn serialize_emailmessage() {
        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .from_ref(Identifier::new_test("email-addr"))
            .unwrap()
            .to_refs([Identifier::new_test("email-addr")].to_vec())
            .unwrap()
            .date(Timestamp("1997-11-21T15:55:06Z".parse().unwrap()))
            .unwrap()
            .subject("Saying Hello".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();
        let mut result = serde_json::to_string_pretty(&email_message).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
            "type": "email-message",
            "is_multipart": false,
            "date": "1997-11-21T15:55:06Z",
            "from_ref": "email-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "to_refs": ["email-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5"],
            "subject": "Saying Hello",
            "spec_version": "2.1",
            "id": "email-message--cc7fa653-c35f-53db-afdd-dce4c3a241d5"
        }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected)
    }

    #[test]
    //checks multipart funtionality with body and body_multipart
    fn emailmessage_multipart_checks() {
        let multipart = EmailMimeCompomentType {
            body: Some("Cats are funny!".to_string()),
            body_raw_ref: None,
            content_type: Some("text/plain; charset=utf-8".to_string()),
            content_disposition: Some("inline".to_string()),
        };

        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .is_multipart()
            .unwrap()
            .body("test".to_string())
            .unwrap()
            .build();
        assert!(email_message.is_err());
        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .body("test".to_string())
            .unwrap()
            .build();
        assert!(email_message.is_ok());
        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .is_multipart()
            .unwrap()
            .body_multipart(vec![multipart.clone()])
            .unwrap()
            .build();
        assert!(email_message.is_ok());
        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .body_multipart(vec![multipart])
            .unwrap()
            .build();
        assert!(email_message.is_err());
    }

    #[test]
    fn emailmessage_referece_check_failure() {
        let multipart = EmailMimeCompomentType {
            body: Some("Cats are funny!".to_string()),
            body_raw_ref: None,
            content_type: Some("text/plain; charset=utf-8".to_string()),
            content_disposition: Some("inline".to_string()),
        };

        // checking from_ref failure positive is in serialization, same as sender_ref
        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .body_multipart(vec![multipart.clone()])
            .unwrap()
            .from_ref(Identifier::new_test("artifact"))
            .unwrap()
            .build();
        assert!(email_message.is_err());
        //check cc_refs: same as to_refs and bcc_refs so only checking the one-positive case is checked in serialization
        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .body_multipart(vec![multipart])
            .unwrap()
            .cc_refs([Identifier::new_test("artifact")].to_vec())
            .unwrap()
            .build();
        assert!(email_message.is_err());
    }

    #[test]
    fn check_raw_email_ref() {
        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .raw_email_ref(Identifier::new_test("artifact"))
            .unwrap()
            .build();
        assert!(email_message.is_ok());
        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .raw_email_ref(Identifier::new_test("email-addr"))
            .unwrap()
            .build();
        assert!(email_message.is_err());
    }
}
