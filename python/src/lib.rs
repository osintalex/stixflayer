use pyo3::exceptions::PyRuntimeError as PyO3RuntimeError;
use pyo3::prelude::*;
use stixflayer::cyber_observable_objects::sco::CyberObjectBuilder;
use stixflayer::domain_objects::sdo::DomainObjectBuilder;
use stixflayer::error::StixError;
use stixflayer::meta_objects::extension_definition::ExtensionDefinitionBuilder;
use stixflayer::meta_objects::language_content::LanguageContentBuilder;
use stixflayer::meta_objects::marking_definition::MarkingDefinitionBuilder;
use stixflayer::object::StixObject;
use stixflayer::relationship_objects::RelationshipObjectBuilder;
use stixflayer::types::ExtensionType;
use stixflayer::types::Identifier;
use stixflayer::types::Timestamp;

#[pyfunction]
pub fn version() -> String {
    "0.1.0".to_string()
}

#[pyfunction]
pub fn test_stix() -> String {
    "STIX 2.1".to_string()
}

#[pyfunction]
pub fn create_timestamp(value: &str) -> String {
    match Timestamp::new(value) {
        Ok(t) => t.to_string(),
        Err(_) => value.to_string(),
    }
}

macro_rules! make_sdo {
    ($name:ident, $type_name:literal) => {
        #[pyclass]
        pub struct $name(DomainObjectBuilder);

        #[pymethods]
        impl $name {
            #[new]
            fn new(name: String) -> Result<Self, PyErr> {
                let builder = DomainObjectBuilder::new($type_name)
                    .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?
                    .name(name)
                    .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
                Ok($name(builder))
            }

            fn to_json(&self) -> String {
                if let Ok(obj) = self.0.clone().build() {
                    serde_json::to_string(&StixObject::Sdo(obj))
                        .unwrap_or_else(|_| "{}".to_string())
                } else {
                    "{}".to_string()
                }
            }

            #[getter]
            fn r#type(&self) -> String {
                $type_name.to_string()
            }
        }
    };
}

macro_rules! make_sdo_optional {
    ($name:ident, $type_name:literal) => {
        #[pyclass]
        pub struct $name(DomainObjectBuilder);

        #[pymethods]
        impl $name {
            #[new]
            fn new(name: Option<String>, description: Option<String>) -> Result<Self, PyErr> {
                let mut builder = DomainObjectBuilder::new($type_name)
                    .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
                if let Some(n) = name {
                    builder = builder
                        .name(n)
                        .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
                }
                if let Some(d) = description {
                    builder = builder
                        .description(d)
                        .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
                }
                Ok($name(builder))
            }

            fn to_json(&self) -> String {
                if let Ok(obj) = self.0.clone().build() {
                    serde_json::to_string(&StixObject::Sdo(obj))
                        .unwrap_or_else(|_| "{}".to_string())
                } else {
                    "{}".to_string()
                }
            }

            #[getter]
            fn r#type(&self) -> String {
                $type_name.to_string()
            }
        }
    };
}

make_sdo!(AttackPattern, "attack-pattern");
make_sdo!(Campaign, "campaign");
make_sdo!(CourseOfAction, "course-of-action");
make_sdo_optional!(Grouping, "grouping");
make_sdo!(Identity, "identity");
make_sdo_optional!(Incident, "incident");
make_sdo_optional!(Indicator, "indicator");
make_sdo_optional!(Infrastructure, "infrastructure");
make_sdo_optional!(IntrusionSet, "intrusion-set");
make_sdo_optional!(Location, "location");
make_sdo_optional!(Malware, "malware");
make_sdo_optional!(MalwareAnalysis, "malware-analysis");
make_sdo_optional!(Note, "note");
make_sdo_optional!(ObservedData, "observed-data");
make_sdo_optional!(Opinion, "opinion");
make_sdo_optional!(Report, "report");
make_sdo_optional!(ThreatActor, "threat-actor");
make_sdo_optional!(Tool, "tool");
make_sdo_optional!(Vulnerability, "vulnerability");

#[pyclass]
pub struct IPv4Address(CyberObjectBuilder);

#[pymethods]
impl IPv4Address {
    #[new]
    fn new(value: String) -> Result<Self, PyErr> {
        let builder = CyberObjectBuilder::new("ipv4-addr")
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?
            .value(value)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(IPv4Address(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            serde_json::to_string(&StixObject::Sco(sco)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "ipv4-addr".to_string()
    }

    #[getter]
    fn value(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            if let stixflayer::cyber_observable_objects::sco::CyberObjectType::Ipv4Addr(ip) =
                &sco.object_type
            {
                return ip.value.clone();
            }
        }
        "".to_string()
    }
}

#[pyclass]
pub struct IPv6Address(CyberObjectBuilder);

#[pymethods]
impl IPv6Address {
    #[new]
    fn new(value: String) -> Result<Self, PyErr> {
        let builder = CyberObjectBuilder::new("ipv6-addr")
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?
            .value(value)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(IPv6Address(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            serde_json::to_string(&StixObject::Sco(sco)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "ipv6-addr".to_string()
    }

    #[getter]
    fn value(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            if let stixflayer::cyber_observable_objects::sco::CyberObjectType::Ipv6Addr(ip) =
                &sco.object_type
            {
                return ip.value.clone();
            }
        }
        "".to_string()
    }
}

#[pyclass]
pub struct DomainName(CyberObjectBuilder);

#[pymethods]
impl DomainName {
    #[new]
    fn new(value: String) -> Result<Self, PyErr> {
        let builder = CyberObjectBuilder::new("domain-name")
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?
            .value(value)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(DomainName(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            serde_json::to_string(&StixObject::Sco(sco)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "domain-name".to_string()
    }

    #[getter]
    fn value(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            if let stixflayer::cyber_observable_objects::sco::CyberObjectType::DomainName(d) =
                &sco.object_type
            {
                return d.value.clone();
            }
        }
        "".to_string()
    }
}

#[pyclass]
pub struct URL(CyberObjectBuilder);

#[pymethods]
impl URL {
    #[new]
    fn new(value: String) -> Result<Self, PyErr> {
        let builder = CyberObjectBuilder::new("url")
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?
            .value(value)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(URL(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            serde_json::to_string(&StixObject::Sco(sco)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "url".to_string()
    }

    #[getter]
    fn value(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            if let stixflayer::cyber_observable_objects::sco::CyberObjectType::Url(u) =
                &sco.object_type
            {
                return u.value.to_string();
            }
        }
        "".to_string()
    }
}

#[pyclass]
pub struct EmailAddress(CyberObjectBuilder);

#[pymethods]
impl EmailAddress {
    #[new]
    fn new(value: String) -> Result<Self, PyErr> {
        let builder = CyberObjectBuilder::new("email-address")
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?
            .value(value)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(EmailAddress(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            serde_json::to_string(&StixObject::Sco(sco)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "email-address".to_string()
    }

    #[getter]
    fn value(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            if let stixflayer::cyber_observable_objects::sco::CyberObjectType::EmailAddress(e) =
                &sco.object_type
            {
                return e.value.clone();
            }
        }
        "".to_string()
    }
}

#[pyclass]
pub struct EmailMessage(CyberObjectBuilder);

#[pymethods]
impl EmailMessage {
    #[new]
    fn new(
        from_ref: String,
        is_multipart: Option<bool>,
        date: Option<String>,
        content_type: Option<String>,
        sender_ref: Option<String>,
        to_refs: Option<Vec<String>>,
        cc_refs: Option<Vec<String>>,
        bcc_refs: Option<Vec<String>>,
        message_id: Option<String>,
        subject: Option<String>,
        recieved_lines: Option<Vec<String>>,
        body: Option<String>,
        raw_email_ref: Option<String>,
    ) -> Result<Self, PyErr> {
        let from: Identifier = from_ref
            .parse()
            .map_err(|_| PyErr::new::<PyO3RuntimeError, _>("Invalid from_ref ID"))?;

        let mut builder = CyberObjectBuilder::new("email-message")
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?
            .from_ref(from)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;

        if is_multipart.unwrap_or(false) {
            builder = builder.is_multipart()
                .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        }

        if let Some(d) = date {
            let ts = Timestamp::new(&d)
                .map_err(|_| PyErr::new::<PyO3RuntimeError, _>("Invalid date format"))?;
            builder = builder.date(ts)
                .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        }

        if let Some(ct) = content_type {
            builder = builder.content_type(ct)
                .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        }

        if let Some(sr) = sender_ref {
            let sender: Identifier = sr
                .parse()
                .map_err(|_| PyErr::new::<PyO3RuntimeError, _>("Invalid sender_ref ID"))?;
            builder = builder.sender_ref(sender)
                .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        }

        if let Some(tr) = to_refs {
            let refs: Vec<Identifier> = tr
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect();
            builder = builder.to_refs(refs)
                .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        }

        if let Some(cr) = cc_refs {
            let refs: Vec<Identifier> = cr
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect();
            builder = builder.cc_refs(refs)
                .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        }

        if let Some(br) = bcc_refs {
            let refs: Vec<Identifier> = br
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect();
            builder = builder.bcc_refs(refs)
                .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        }

        if let Some(mid) = message_id {
            builder = builder.message_id(mid)
                .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        }

        if let Some(s) = subject {
            builder = builder.subject(s)
                .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        }

        if let Some(rl) = recieved_lines {
            builder = builder.recieved_lines(rl)
                .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        }

        if let Some(b) = body {
            builder = builder.body(b)
                .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        }

        if let Some(re) = raw_email_ref {
            let raw: Identifier = re
                .parse()
                .map_err(|_| PyErr::new::<PyO3RuntimeError, _>("Invalid raw_email_ref ID"))?;
            builder = builder.raw_email_ref(raw)
                .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        }

        Ok(EmailMessage(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            serde_json::to_string(&StixObject::Sco(sco)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "email-message".to_string()
    }

    #[getter]
    fn from_ref(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            if let stixflayer::cyber_observable_objects::sco::CyberObjectType::EmailMessage(em) =
                &sco.object_type
            {
                return em.from_ref.clone().map(|i| i.to_string()).unwrap_or_default();
            }
        }
        "".to_string()
    }
}

#[pyclass]
pub struct MacAddr(CyberObjectBuilder);

#[pymethods]
impl MacAddr {
    #[new]
    fn new(value: String) -> Result<Self, PyErr> {
        let builder = CyberObjectBuilder::new("mac-addr")
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?
            .value(value)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(MacAddr(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            serde_json::to_string(&StixObject::Sco(sco)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "mac-addr".to_string()
    }

    #[getter]
    fn value(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            if let stixflayer::cyber_observable_objects::sco::CyberObjectType::MacAddr(m) =
                &sco.object_type
            {
                return m.value.clone();
            }
        }
        "".to_string()
    }
}

#[pyclass]
pub struct AutonomousSystem(CyberObjectBuilder);

#[pymethods]
impl AutonomousSystem {
    #[new]
    fn new(number: u64) -> Result<Self, PyErr> {
        let builder = CyberObjectBuilder::new("autonomous-system")
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?
            .number(number)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(AutonomousSystem(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            serde_json::to_string(&StixObject::Sco(sco)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "autonomous-system".to_string()
    }

    #[getter]
    fn number(&self) -> u64 {
        if let Ok(sco) = self.0.clone().build() {
            if let stixflayer::cyber_observable_objects::sco::CyberObjectType::AutonomousSystem(
                obj,
            ) = &sco.object_type
            {
                return obj.number;
            }
        }
        0
    }
}

#[pyclass]
pub struct File(CyberObjectBuilder);

#[pymethods]
impl File {
    #[new]
    fn new(name: String) -> Result<Self, PyErr> {
        let builder = CyberObjectBuilder::new("file")
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?
            .name(name)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(File(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            serde_json::to_string(&StixObject::Sco(sco)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "file".to_string()
    }

    #[getter]
    fn name(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            if let stixflayer::cyber_observable_objects::sco::CyberObjectType::File(f) =
                &sco.object_type
            {
                return f.name.clone().unwrap_or_default();
            }
        }
        "".to_string()
    }
}

#[pyclass]
pub struct Software(CyberObjectBuilder);

#[pymethods]
impl Software {
    #[new]
    fn new(name: String) -> Result<Self, PyErr> {
        let builder = CyberObjectBuilder::new("software")
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?
            .name(name)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(Software(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            serde_json::to_string(&StixObject::Sco(sco)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "software".to_string()
    }

    #[getter]
    fn name(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            if let stixflayer::cyber_observable_objects::sco::CyberObjectType::Software(s) =
                &sco.object_type
            {
                return s.name.clone();
            }
        }
        "".to_string()
    }
}

#[pyclass]
pub struct Directory(CyberObjectBuilder);

#[pymethods]
impl Directory {
    #[new]
    fn new(path: String) -> Result<Self, PyErr> {
        let builder = CyberObjectBuilder::new("directory")
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?
            .path(path)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(Directory(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            serde_json::to_string(&StixObject::Sco(sco)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "directory".to_string()
    }

    #[getter]
    fn path(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            if let stixflayer::cyber_observable_objects::sco::CyberObjectType::Directory(d) =
                &sco.object_type
            {
                return d.path.clone();
            }
        }
        "".to_string()
    }
}

#[pyclass]
pub struct Mutex(CyberObjectBuilder);

#[pymethods]
impl Mutex {
    #[new]
    fn new(name: String) -> Result<Self, PyErr> {
        let builder = CyberObjectBuilder::new("mutex")
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?
            .name(name)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(Mutex(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            serde_json::to_string(&StixObject::Sco(sco)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "mutex".to_string()
    }

    #[getter]
    fn name(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            if let stixflayer::cyber_observable_objects::sco::CyberObjectType::Mutex(m) =
                &sco.object_type
            {
                return m.name.clone();
            }
        }
        "".to_string()
    }
}

#[pyclass]
pub struct Process(CyberObjectBuilder);

#[pymethods]
impl Process {
    #[new]
    fn new() -> Result<Self, PyErr> {
        let builder = CyberObjectBuilder::new("process")
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(Process(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            serde_json::to_string(&StixObject::Sco(sco)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "process".to_string()
    }
}

#[pyclass]
pub struct NetworkTraffic(CyberObjectBuilder);

#[pymethods]
impl NetworkTraffic {
    #[new]
    fn new(protocols: Vec<String>) -> Result<Self, PyErr> {
        let builder = CyberObjectBuilder::new("network-traffic")
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?
            .protocols(protocols)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(NetworkTraffic(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            serde_json::to_string(&StixObject::Sco(sco)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "network-traffic".to_string()
    }
}

#[pyclass]
pub struct UserAccount(CyberObjectBuilder);

#[pymethods]
impl UserAccount {
    #[new]
    fn new(account_login: String) -> Result<Self, PyErr> {
        let builder = CyberObjectBuilder::new("user-account")
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?
            .account_login(account_login)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(UserAccount(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            serde_json::to_string(&StixObject::Sco(sco)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "user-account".to_string()
    }

    #[getter]
    fn account_login(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            if let stixflayer::cyber_observable_objects::sco::CyberObjectType::UserAccount(u) =
                &sco.object_type
            {
                return u.account_login.clone().unwrap_or_default();
            }
        }
        "".to_string()
    }
}

#[pyclass]
pub struct WindowsRegistryKey(CyberObjectBuilder);

#[pymethods]
impl WindowsRegistryKey {
    #[new]
    fn new(key: String) -> Result<Self, PyErr> {
        let builder = CyberObjectBuilder::new("windows-registry-key")
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?
            .key(key)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(WindowsRegistryKey(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            serde_json::to_string(&StixObject::Sco(sco)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "windows-registry-key".to_string()
    }

    #[getter]
    fn key(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            if let stixflayer::cyber_observable_objects::sco::CyberObjectType::WindowsRegistryKey(
                w,
            ) = &sco.object_type
            {
                return w.key.clone().unwrap_or_default();
            }
        }
        "".to_string()
    }
}

#[pyclass]
pub struct X509Certificate(CyberObjectBuilder);

#[pymethods]
impl X509Certificate {
    #[new]
    fn new(serial_number: String) -> Result<Self, PyErr> {
        let builder = CyberObjectBuilder::new("x509-certificate")
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?
            .serial_number(serial_number)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(X509Certificate(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            serde_json::to_string(&StixObject::Sco(sco)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "x509-certificate".to_string()
    }

    #[getter]
    fn serial_number(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            if let stixflayer::cyber_observable_objects::sco::CyberObjectType::X509Certificate(x) =
                &sco.object_type
            {
                return x.serial_number.clone().unwrap_or_default();
            }
        }
        "".to_string()
    }
}

#[pyclass]
pub struct Artifact(CyberObjectBuilder);

#[pymethods]
impl Artifact {
    #[new]
    fn new(mime_type: String) -> Result<Self, PyErr> {
        let builder = CyberObjectBuilder::new("artifact")
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?
            .mime_type(mime_type)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(Artifact(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            serde_json::to_string(&StixObject::Sco(sco)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "artifact".to_string()
    }

    #[getter]
    fn mime_type(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            if let stixflayer::cyber_observable_objects::sco::CyberObjectType::Artifact(a) =
                &sco.object_type
            {
                return a.mime_type.clone().unwrap_or_default();
            }
        }
        "".to_string()
    }
}

#[pyclass]
pub struct Relationship(RelationshipObjectBuilder);

#[pymethods]
impl Relationship {
    #[new]
    fn new(
        source_ref: String,
        target_ref: String,
        relationship_type: String,
    ) -> Result<Self, PyErr> {
        let source: Identifier = source_ref
            .parse()
            .map_err(|_| PyErr::new::<PyO3RuntimeError, _>("Invalid source ID"))?;
        let target: Identifier = target_ref
            .parse()
            .map_err(|_| PyErr::new::<PyO3RuntimeError, _>("Invalid target ID"))?;

        let builder = RelationshipObjectBuilder::new(source, target, &relationship_type)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(Relationship(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(obj) = self.0.clone().build() {
            serde_json::to_string(&StixObject::Sro(obj)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "relationship".to_string()
    }
}

#[pyclass]
pub struct Sighting(RelationshipObjectBuilder);

#[pymethods]
impl Sighting {
    #[new]
    fn new(sighting_of_ref: String) -> Result<Self, PyErr> {
        let sighting_of: Identifier = sighting_of_ref
            .parse()
            .map_err(|_| PyErr::new::<PyO3RuntimeError, _>("Invalid ID"))?;

        let builder = RelationshipObjectBuilder::new_sighting(sighting_of)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(Sighting(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(obj) = self.0.clone().build() {
            serde_json::to_string(&StixObject::Sro(obj)).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "sighting".to_string()
    }
}

#[pyclass]
pub struct MarkingDefinition(MarkingDefinitionBuilder);

#[pymethods]
impl MarkingDefinition {
    #[new]
    fn new(definition_type: String) -> Result<Self, PyErr> {
        let mut builder = MarkingDefinitionBuilder::new()
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        builder = builder.definition_type(definition_type);
        Ok(MarkingDefinition(builder))
    }

    fn to_json(&self) -> String {
        if let Ok(obj) = self.0.clone().build() {
            serde_json::to_string(&obj).unwrap_or_else(|_| "{}".to_string())
        } else {
            "{}".to_string()
        }
    }

    #[getter]
    fn r#type(&self) -> String {
        "marking-definition".to_string()
    }
}

#[pyclass]
pub struct ExtensionDefinition(ExtensionDefinitionBuilder);

#[pymethods]
impl ExtensionDefinition {
    #[new]
    fn new(
        name: String,
        schema: String,
        version: String,
        extension_type: String,
    ) -> Result<Self, PyErr> {
        let mut builder = ExtensionDefinitionBuilder::new(&name)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        builder = builder.schema(schema);
        builder = builder.set_version(version);
        let ext_type = match extension_type.as_str() {
            "new-sdo" => ExtensionType::NewSdo,
            "new-sco" => ExtensionType::NewSco,
            "new-sro" => ExtensionType::NewSro,
            "property" => ExtensionType::PropertyExtension,
            _ => ExtensionType::ToplevelPropertyExtension,
        };
        builder = builder.extension_types(vec![ext_type]);
        Ok(ExtensionDefinition(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        self.0
            .clone()
            .build()
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))
            .and_then(|obj| {
                serde_json::to_string(&obj)
                    .map_err(|e| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))
            })
    }

    #[getter]
    fn r#type(&self) -> String {
        "extension-definition".to_string()
    }
}

#[pyclass]
pub struct LanguageContent(LanguageContentBuilder);

#[pymethods]
impl LanguageContent {
    #[new]
    fn new(object_ref: String) -> Result<Self, PyErr> {
        let builder = LanguageContentBuilder::new(&object_ref)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(LanguageContent(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        self.0
            .clone()
            .build()
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))
            .and_then(|obj| {
                serde_json::to_string(&obj)
                    .map_err(|e| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))
            })
    }

    #[getter]
    fn r#type(&self) -> String {
        "language-content".to_string()
    }

    fn insert_content_strings(
        &mut self,
        lang: String,
        content: pyo3::Bound<'_, pyo3::types::PyDict>,
    ) -> Result<(), PyErr> {
        let hashmap: std::collections::HashMap<String, String> = content.extract().map_err(|e| {
            PyErr::new::<PyO3RuntimeError, _>(format!("Failed to extract content: {}", e))
        })?;
        self.0 = self.0.clone()
            .insert_content_strings(&lang, hashmap)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(())
    }

    fn insert_content_lists(
        &mut self,
        lang: String,
        content: pyo3::Bound<'_, pyo3::types::PyDict>,
    ) -> Result<(), PyErr> {
        let hashmap: std::collections::HashMap<String, Vec<String>> = content.extract().map_err(|e| {
            PyErr::new::<PyO3RuntimeError, _>(format!("Failed to extract content: {}", e))
        })?;
        self.0 = self.0.clone()
            .insert_content_lists(&lang, hashmap)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(())
    }

    fn insert_content_objects(
        &mut self,
        lang: String,
        content: pyo3::Bound<'_, pyo3::types::PyDict>,
    ) -> Result<(), PyErr> {
        let _py = content.py();
        let mut hashmap: std::collections::HashMap<String, std::collections::HashMap<String, serde_json::Value>> = std::collections::HashMap::new();
        
        for (key, value) in content.iter() {
            let k: String = key.extract().map_err(|e| {
                PyErr::new::<PyO3RuntimeError, _>(format!("Failed to extract key: {}", e))
            })?;
            
            if value.is_none() {
                continue;
            }
            
            let v: pyo3::Bound<'_, pyo3::types::PyDict> = value.extract().map_err(|e| {
                PyErr::new::<PyO3RuntimeError, _>(format!("Failed to extract nested dict: {}", e))
            })?;
            
            let mut inner_hashmap = std::collections::HashMap::new();
            for (inner_key, inner_value) in v.iter() {
                let ik: String = inner_key.extract().map_err(|e| {
                    PyErr::new::<PyO3RuntimeError, _>(format!("Failed to extract inner key: {}", e))
                })?;
                
                if inner_value.is_none() {
                    inner_hashmap.insert(ik, serde_json::Value::String(String::new()));
                    continue;
                }
                
                if let Ok(s) = inner_value.extract::<String>() {
                    inner_hashmap.insert(ik, serde_json::Value::String(s));
                } else if let Ok(arr) = inner_value.extract::<Vec<String>>() {
                    inner_hashmap.insert(ik, serde_json::Value::Array(arr.into_iter().map(serde_json::Value::String).collect()));
                } else {
                    inner_hashmap.insert(ik, serde_json::Value::String(String::new()));
                }
            }
            hashmap.insert(k, inner_hashmap);
        }
        
        self.0 = self.0.clone()
            .insert_content_objects(&lang, hashmap)
            .map_err(|e: StixError| PyErr::new::<PyO3RuntimeError, _>(e.to_string()))?;
        Ok(())
    }

    #[getter]
    fn object_ref(&self) -> String {
        self.0.clone().build()
            .map(|lc| lc.object_ref.to_string())
            .unwrap_or_default()
    }
}

#[pymodule(name = "stixflayer")]
pub fn stixflayer_bindings(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(test_stix, m)?)?;
    m.add_function(wrap_pyfunction!(create_timestamp, m)?)?;

    m.add_class::<AttackPattern>()?;
    m.add_class::<Campaign>()?;
    m.add_class::<CourseOfAction>()?;
    m.add_class::<Grouping>()?;
    m.add_class::<Identity>()?;
    m.add_class::<Incident>()?;
    m.add_class::<Indicator>()?;
    m.add_class::<Infrastructure>()?;
    m.add_class::<IntrusionSet>()?;
    m.add_class::<Location>()?;
    m.add_class::<Malware>()?;
    m.add_class::<MalwareAnalysis>()?;
    m.add_class::<Note>()?;
    m.add_class::<ObservedData>()?;
    m.add_class::<Opinion>()?;
    m.add_class::<Report>()?;
    m.add_class::<ThreatActor>()?;
    m.add_class::<Tool>()?;
    m.add_class::<Vulnerability>()?;

    m.add_class::<IPv4Address>()?;
    m.add_class::<IPv6Address>()?;
    m.add_class::<DomainName>()?;
    m.add_class::<URL>()?;
    m.add_class::<EmailAddress>()?;
    m.add_class::<EmailMessage>()?;
    m.add_class::<MacAddr>()?;
    m.add_class::<AutonomousSystem>()?;
    m.add_class::<File>()?;
    m.add_class::<Software>()?;
    m.add_class::<Directory>()?;
    m.add_class::<Mutex>()?;
    m.add_class::<Process>()?;
    m.add_class::<NetworkTraffic>()?;
    m.add_class::<UserAccount>()?;
    m.add_class::<WindowsRegistryKey>()?;
    m.add_class::<X509Certificate>()?;
    m.add_class::<Artifact>()?;

    m.add_class::<Relationship>()?;
    m.add_class::<Sighting>()?;
    m.add_class::<MarkingDefinition>()?;
    m.add_class::<ExtensionDefinition>()?;
    m.add_class::<LanguageContent>()?;

    Ok(())
}
