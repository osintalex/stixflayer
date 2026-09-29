use crate::base::Stix;
use crate::types::{Hashes, Timestamp};
use crate::error::{add_error, return_multiple_errors, StixError as Error};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;
use serde_this_or_that::{as_opt_i64};

/// X.509 Certificate
///
/// The X.509 Certificate object represents the properties of an X.509 certificate, as defined by ITU recommendation X.509 [X.509].
/// An X.509 Certificate object **MUST** contain at least one object specific property (other than type) from this object.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_8abcy1o5x9w1>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct X509Certificate {
    /// Specifies whether the certificate is self-signed, i.e., whether it is signed by the same entity whose identity it certifies.
    pub is_self_signed: Option<bool>,
    /// Specifies any hashes that were calculated for the entire contents of the certificate.
    pub hashes: Option<Hashes>,
    /// Specifies the version of the encoded certificate.
    pub version: Option<String>,
    /// Specifies the unique identifier for the certificate, as issued by a specific Certificate Authority.
    pub serial_number: Option<String>,
    /// Specifies the name of the algorithm used to sign the certificate.
    pub signature_algorithm: Option<String>,
    /// Specifies the name of the Certificate Authority that issued the certificate.
    pub issuer: Option<String>,
    /// Specifies the date on which the certificate validity period begins.
    pub validity_not_before: Option<Timestamp>,
    /// Specifies the date on which the certificate validity period ends.
    pub validity_not_after: Option<Timestamp>,
    /// Specifies the name of the entity associated with the public key stored in the subject public key field of the certificate.
    pub subject: Option<String>,
    /// Specifies the name of the algorithm with which to encrypt data being sent to the subject.
    pub subject_public_key_algorithm: Option<String>,
    /// Specifies the modulus portion of the subject’s public RSA key.
    pub subject_public_key_modulus: Option<String>,
    /// Specifies the exponent portion of the subject’s public RSA key, as an integer.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub subject_public_key_exponent: Option<i64>,
    /// Specifies any standard X.509 v3 extensions that may be used in the certificate.
    #[serde(rename = "x509_v3_extensions", alias = "extensions", default)]
    pub x509_v3_extensions: Option<X509V3Extensions>,
}
impl Stix for X509Certificate {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(hashes) = &self.hashes {
            add_error(&mut errors, hashes.stix_check());
        }

        // Validate subject_public_key_exponent
        if let Some(exponent) = self.subject_public_key_exponent {
            if exponent <= 0 {
                errors.push(Error::ValidationError(
                    "subject_public_key_exponent must be a positive integer".to_string(),
                ));
            }
        }

        // Validate x509_v3_extensions if present
        if let Some(extensions) = &self.x509_v3_extensions {
            add_error(&mut errors, extensions.stix_check());
        }
        if let Some(subject_public_key_exponent) = &self.subject_public_key_exponent {
            add_error(&mut errors, subject_public_key_exponent.stix_check());
        }
        return_multiple_errors(errors)
    }
}

/// X.509 v3 Extensions
///
/// The X.509 v3 Extensions object represents the properties of the X.509 v3 extensions that may be used in the certificate.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_oudvonxzdlku>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X509V3Extensions {
    /// Specifies a multi-valued extension which indicates whether a certificate is a CA certificate.
    pub basic_constraints: Option<String>,
    /// Specifies a namespace within which all subject names in subsequent certificates in a certification path MUST be located.
    pub name_constraints: Option<String>,
    /// Specifies any constraints on path validation for certificates issued to CAs.
    pub policy_constraints: Option<String>,
    /// Specifies a multi-valued extension consisting of a list of names of the permitted key usages.
    pub key_usage: Option<String>,
    /// Specifies a list of usages indicating purposes for which the certificate public key can be used for.
    pub extended_key_usage: Option<String>,
    /// Specifies the identifier that provides a means of identifying certificates that contain a particular public key.
    pub subject_key_identifier: Option<String>,
    /// Specifies the identifier that provides a means of identifying the public key corresponding to the private key used to sign a certificate.
    pub authority_key_identifier: Option<String>,
    /// Specifies the additional identities to be bound to the subject of the certificate.
    pub subject_alternative_name: Option<String>,
    /// Specifies the additional identities to be bound to the issuer of the certificate.
    pub issuer_alternative_name: Option<String>,
    /// Specifies the identification attributes (e.g., nationality) of the subject.
    pub subject_directory_attributes: Option<String>,
    /// Specifies how CRL information is obtained.
    pub crl_distribution_points: Option<String>,
    /// Specifies the number of additional certificates that may appear in the path before anyPolicy is no longer permitted.
    pub inhibit_any_policy: Option<String>,
    /// Specifies the date on which the validity period begins for the private key, if it is different from the validity period of the certificate.
    pub private_key_usage_period_not_before: Option<Timestamp>,
    /// Specifies the date on which the validity period ends for the private key, if it is different from the validity period of the certificate.
    pub private_key_usage_period_not_after: Option<Timestamp>,
    /// Specifies a sequence of one or more policy information terms, each of which consists of an object identifier (OID) and optional qualifiers.
    pub certificate_policies: Option<String>,
    /// Specifies one or more pairs of OIDs; each pair includes an issuerDomainPolicy and a subjectDomainPolicy.
    pub policy_mappings: Option<String>,
}

impl Stix for X509V3Extensions {
    fn stix_check(&self) -> Result<(), Error> {
        // Ensure at least one property is present
        if self.basic_constraints.is_none()
            && self.name_constraints.is_none()
            && self.policy_constraints.is_none()
            && self.key_usage.is_none()
            && self.extended_key_usage.is_none()
            && self.subject_key_identifier.is_none()
            && self.authority_key_identifier.is_none()
            && self.subject_alternative_name.is_none()
            && self.issuer_alternative_name.is_none()
            && self.subject_directory_attributes.is_none()
            && self.crl_distribution_points.is_none()
            && self.inhibit_any_policy.is_none()
            && self.private_key_usage_period_not_before.is_none()
            && self.private_key_usage_period_not_after.is_none()
            && self.certificate_policies.is_none()
            && self.policy_mappings.is_none()
        {
            return Err(Error::ValidationError(
                "An X.509 v3 Extensions object must contain at least one property.".to_string(),
            ));
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
    use super::X509V3Extensions;

    #[test]
    fn serialize_x509_certificate() {
        let x509_certificate = CyberObjectBuilder::new("x509-certificate")
            .unwrap()
            .issuer("C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com".to_string())
            .unwrap()
            .validity_not_before(Timestamp("2016-03-12T12:00:00Z".parse().unwrap()))
            .unwrap()
            .validity_not_after(Timestamp("2016-08-21T12:00:00Z".parse().unwrap()))
            .unwrap()
            .subject("C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org".to_string())
            .unwrap()
            .serial_number("36:f7:d4:32:f4:ab:70:ea:d3:ce:98:6e:ea:99:93:49:32:0a:b7:06".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let result = serde_json::to_string_pretty(&x509_certificate).unwrap();
        let result_value: serde_json::Value = serde_json::from_str(&result).unwrap();

        let expected = r#"
        {
            "type": "x509-certificate",
            "spec_version": "2.1",
            "id": "x509-certificate--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "issuer": "C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com",
            "validity_not_before": "2016-03-12T12:00:00Z",
            "validity_not_after": "2016-08-21T12:00:00Z",
            "subject": "C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org",
            "serial_number": "36:f7:d4:32:f4:ab:70:ea:d3:ce:98:6e:ea:99:93:49:32:0a:b7:06"
        }"#;
        let expected_value: serde_json::Value = serde_json::from_str(expected).unwrap();

        assert_eq!(result_value, expected_value);
    }

    #[test]
    fn deserialize_x509_certificate() {
        let json = r#"
        {
            "type": "x509-certificate",
            "spec_version": "2.1",
            "id": "x509-certificate--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "issuer": "C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com",
            "validity_not_before": "2016-03-12T12:00:00Z",
            "validity_not_after": "2016-08-21T12:00:00Z",
            "subject": "C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org",
            "serial_number": "36:f7:d4:32:f4:ab:70:ea:d3:ce:98:6e:ea:99:93:49:32:0a:b7:06"
        }"#;

        let result = CyberObject::from_json(json, false).unwrap();
        let expected = CyberObjectBuilder::new("x509-certificate")
            .unwrap()
            .issuer("C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com".to_string())
            .unwrap()
            .validity_not_before(Timestamp("2016-03-12T12:00:00Z".parse().unwrap()))
            .unwrap()
            .validity_not_after(Timestamp("2016-08-21T12:00:00Z".parse().unwrap()))
            .unwrap()
            .subject("C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org".to_string())
            .unwrap()
            .serial_number("36:f7:d4:32:f4:ab:70:ea:d3:ce:98:6e:ea:99:93:49:32:0a:b7:06".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        assert_eq!(result, expected);
    }

    #[test]
    fn serialize_x509_certificate_with_v3_extensions() {
        let certificate_extension = X509V3Extensions {
            basic_constraints: Some("critical,CA:TRUE, pathlen:0".to_string()),
            name_constraints: Some("permitted;IP:192.168.0.0/255.255.0.0".to_string()),
            policy_constraints: Some("requireExplicitPolicy:3".to_string()),
            key_usage: Some("critical, keyCertSign".to_string()),
            extended_key_usage: Some("critical,codeSigning,1.2.3.4".to_string()),
            subject_key_identifier: Some("hash".to_string()),
            authority_key_identifier: Some("keyid,issuer".to_string()),
            subject_alternative_name: Some("email:my@other.address,RID:1.2.3.4".to_string()),
            issuer_alternative_name: Some("issuer:copy".to_string()),
            subject_directory_attributes: None,
            crl_distribution_points: Some("URI:http://myhost.com/myca.crl".to_string()),
            inhibit_any_policy: Some("2".to_string()),
            private_key_usage_period_not_before: Some(Timestamp(
                "2016-03-12T12:00:00Z".parse().unwrap(),
            )),
            private_key_usage_period_not_after: Some(Timestamp(
                "2018-03-12T12:00:00Z".parse().unwrap(),
            )),
            certificate_policies: Some("1.2.4.5, 1.1.3.4".to_string()),
            policy_mappings: None,
        };

        let x509_certificate = CyberObjectBuilder::new("x509-certificate")
            .unwrap()
            .issuer("C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com".to_string())
            .unwrap()
            .validity_not_before(Timestamp("2016-03-12T12:00:00Z".parse().unwrap()))
            .unwrap()
            .validity_not_after(Timestamp("2016-08-21T12:00:00Z".parse().unwrap()))
            .unwrap()
            .subject("C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org".to_string())
            .unwrap()
            .serial_number("36:f7:d4:32:f4:ab:70:ea:d3:ce:98:6e:ea:99:93:49:32:0a:b7:06".to_string())
            .unwrap()
            .x509_v3_extensions(certificate_extension)
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let result = serde_json::to_value(&x509_certificate).unwrap();

        let expected = r#"
        {
            "type": "x509-certificate",
            "spec_version": "2.1",
            "id": "x509-certificate--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "issuer": "C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com",
            "validity_not_before": "2016-03-12T12:00:00Z",
            "validity_not_after": "2016-08-21T12:00:00Z",
            "subject": "C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org",
            "serial_number": "36:f7:d4:32:f4:ab:70:ea:d3:ce:98:6e:ea:99:93:49:32:0a:b7:06",
            "x509_v3_extensions":{
                "basic_constraints":"critical,CA:TRUE, pathlen:0",
                "name_constraints":"permitted;IP:192.168.0.0/255.255.0.0",
                "policy_constraints":"requireExplicitPolicy:3",
                "key_usage":"critical, keyCertSign",
                "extended_key_usage":"critical,codeSigning,1.2.3.4",
                "subject_key_identifier":"hash",
                "authority_key_identifier":"keyid,issuer",
                "subject_alternative_name":"email:my@other.address,RID:1.2.3.4",
                "issuer_alternative_name":"issuer:copy",
                "crl_distribution_points":"URI:http://myhost.com/myca.crl",
                "inhibit_any_policy":"2",
                "private_key_usage_period_not_before":"2016-03-12T12:00:00Z",
                "private_key_usage_period_not_after":"2018-03-12T12:00:00Z",
                "certificate_policies":"1.2.4.5, 1.1.3.4"
            }
        }"#;
        let expected: serde_json::Value = serde_json::from_str(expected).unwrap();

        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_x509_certificate_with_v3_extensions() {
        let json = r#"
        {
            "type": "x509-certificate",
            "spec_version": "2.1",
            "id": "x509-certificate--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "issuer": "C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com",
            "validity_not_before": "2016-03-12T12:00:00Z",
            "validity_not_after": "2016-08-21T12:00:00Z",
            "subject": "C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org",
            "serial_number": "36:f7:d4:32:f4:ab:70:ea:d3:ce:98:6e:ea:99:93:49:32:0a:b7:06",
            "x509_v3_extensions":{
                "basic_constraints":"critical,CA:TRUE, pathlen:0",
                "name_constraints":"permitted;IP:192.168.0.0/255.255.0.0",
                "policy_constraints":"requireExplicitPolicy:3",
                "key_usage":"critical, keyCertSign",
                "extended_key_usage":"critical,codeSigning,1.2.3.4",
                "subject_key_identifier":"hash",
                "authority_key_identifier":"keyid,issuer",
                "subject_alternative_name":"email:my@other.address,RID:1.2.3.4",
                "issuer_alternative_name":"issuer:copy",
                "crl_distribution_points":"URI:http://myhost.com/myca.crl",
                "inhibit_any_policy":"2",
                "private_key_usage_period_not_before":"2016-03-12T12:00:00Z",
                "private_key_usage_period_not_after":"2018-03-12T12:00:00Z",
                "certificate_policies":"1.2.4.5, 1.1.3.4"
            }
        }"#;

        let result = CyberObject::from_json(json, false).unwrap();
        let certificate_extension = X509V3Extensions {
            basic_constraints: Some("critical,CA:TRUE, pathlen:0".to_string()),
            name_constraints: Some("permitted;IP:192.168.0.0/255.255.0.0".to_string()),
            policy_constraints: Some("requireExplicitPolicy:3".to_string()),
            key_usage: Some("critical, keyCertSign".to_string()),
            extended_key_usage: Some("critical,codeSigning,1.2.3.4".to_string()),
            subject_key_identifier: Some("hash".to_string()),
            authority_key_identifier: Some("keyid,issuer".to_string()),
            subject_alternative_name: Some("email:my@other.address,RID:1.2.3.4".to_string()),
            issuer_alternative_name: Some("issuer:copy".to_string()),
            subject_directory_attributes: None,
            crl_distribution_points: Some("URI:http://myhost.com/myca.crl".to_string()),
            inhibit_any_policy: Some("2".to_string()),
            private_key_usage_period_not_before: Some(Timestamp(
                "2016-03-12T12:00:00Z".parse().unwrap(),
            )),
            private_key_usage_period_not_after: Some(Timestamp(
                "2018-03-12T12:00:00Z".parse().unwrap(),
            )),
            certificate_policies: Some("1.2.4.5, 1.1.3.4".to_string()),
            policy_mappings: None,
        };

        let expected = CyberObjectBuilder::new("x509-certificate")
            .unwrap()
            .issuer("C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com".to_string())
            .unwrap()
            .validity_not_before(Timestamp("2016-03-12T12:00:00Z".parse().unwrap()))
            .unwrap()
            .validity_not_after(Timestamp("2016-08-21T12:00:00Z".parse().unwrap()))
            .unwrap()
            .subject("C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org".to_string())
            .unwrap()
            .serial_number("36:f7:d4:32:f4:ab:70:ea:d3:ce:98:6e:ea:99:93:49:32:0a:b7:06".to_string())
            .unwrap()
            .x509_v3_extensions(certificate_extension)
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        assert_eq!(result, expected);
    }
}
