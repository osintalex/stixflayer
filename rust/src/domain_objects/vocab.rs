//! Enumerations for standardizing and categorizing types for SDOs.

use serde::{Deserialize, Serialize};
use strum::{AsRefStr, EnumIter};

/// Represents the different processor architectures within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum ArchitectureExecutionEnvs {
    /// Specifies the Alpha architecture.
    Alpha,
    /// Specifies the ARM architecture.
    Arm,
    /// Specifies the 64-bit IA (Itanium) architecture.
    #[strum(serialize = "ia-64")]
    Ia64,
    /// Specifies the MIPS architecture.
    Mips,
    /// Specifies the PowerPC architecture.
    #[strum(serialize = "powerpc")]
    PowerPC,
    /// Specifies the SPARC architecture.
    Sparc,
    /// Specifies the 32-bit x86 architecture.
    X86,
    /// Specifies the 64-bit x86 architecture.
    X86_64,
}

/// Represents attack motivations used in Intrusion Set and Threat Actor SDOs within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum AttackMotivation {
    /// A non-hostile actor whose benevolent or harmless intent inadvertently causes harm.
    Accidental,
    /// Being forced to act on someone else's behalf, often through intimidation or blackmail.
    Coercion,
    /// A desire to assert superiority over someone or something else.
    Dominance,
    /// A passion to express a set of ideas, beliefs, and values that may drive harmful acts.
    Ideology,
    /// Seeking prestige or to become well known through some activity.
    Notoriety,
    /// Seeking advantage over a competing organization, including a military organization.
    OrganizationalGain,
    /// The desire to improve one’s own financial status.
    PersonalGain,
    /// A desire to satisfy a strictly personal goal, including curiosity or thrill-seeking.
    PersonalSatisfaction,
    /// A desire to avenge perceived wrongs through harmful actions.
    Revenge,
    /// Acting without identifiable reason or purpose, creating unpredictable events.
    Unpredictable,
}

/// Represents the resource levels available to threat actors within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum AttackResourceLevel {
    /// Resources limited to the average individual; Threat Actor acts independently.
    Individual,
    /// Members interact on a social and volunteer basis, often with little personal interest in the specific target.
    Club,
    /// A short-lived interaction that concludes when participants achieve a single goal.
    Contest,
    /// A formally organized group with a leader, motivated by a specific goal.
    Team,
    /// Larger and better resourced than a team; typically a company or crime syndicate.
    Organization,
    /// Controls public assets and functions within a jurisdiction; very well resourced.
    Government,
}

/// Represents different types of contexts within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter, Default)]
#[strum(serialize_all = "kebab-case")]
pub enum ContextType {
    /// A grouping of objects related to suspicious activity.
    SuspiciousActivity,
    /// A grouping of objects related to malware analysis.
    MalwareAnalysis,
    /// A grouping of objects whose context is not otherwise specified.
    #[default]
    Unspecified,
}

/// Represents the type of entity that an Identity represents within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum IdentityClass {
    /// A single person.
    Individual,
    /// A formal or informal collection of people.
    Group,
    /// A computer, program, or other electronic device.
    System,
    /// A company, agency, or other organized entity.
    Organization,
    /// A general type of entity, such as banks or universities.
    Class,
    /// The identity class is not known.
    Unknown,
}

/// Represents various identity sectors within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum IdentitySectors {
    /// The agriculture sector.
    Agriculture,
    /// The aerospace sector.
    Aerospace,
    /// The automotive sector.
    Automotive,
    /// The communications sector.
    Communications,
    /// The construction sector.
    Construction,
    /// The defence sector.
    Defence,
    /// The education sector.
    Education,
    /// The energy sector.
    Energy,
    /// The entertainment sector.
    Entertainment,
    /// The financial services sector.
    FinancialServices,
    /// The national government sector.
    GovernmentNational,
    /// The regional government sector.
    GovernmentRegional,
    /// The local government sector.
    GovernmentLocal,
    /// The government public services sector.
    GovernmentPublicServices,
    /// The emergency services sector.
    EmergencyServices,
    /// The healthcare sector.
    Healthcare,
    /// The hospitality and leisure sector.
    HospitalityLeisure,
    /// The infrastructure sector.
    Infrastructure,
    /// The insurance sector.
    Insurance,
    /// The manufacturing sector.
    Manufacturing,
    /// The mining sector.
    Mining,
    /// The non-profit sector.
    NonProfit,
    /// The pharmaceuticals sector.
    Pharmaceuticals,
    /// The retail sector.
    Retail,
    /// The technology sector.
    Technology,
    /// The telecommunications sector.
    Telecommunications,
    /// The transportation sector.
    Transportation,
    /// The utilities sector.
    Utilities,
}

/// Represents different programming languages within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum ImplementationLanguage {
    /// Specifies the AppleScript programming language.
    #[strum(serialize = "applescript")]
    AppleScript,
    /// Specifies the Bash Implementation language.
    Bash,
    /// Specifies the C Implementation language.
    C,
    /// Specifies the C++ Implementation language.
    #[strum(serialize = "c++")]
    CPlusPlus,
    /// Specifies the C# Implementation language.
    #[strum(serialize = "c#")]
    CSharp,
    /// Specifies the Go Implementation language.
    Go,
    /// Specifies the Java Implementation language.
    Java,
    /// Specifies the JavaScript Implementation language.
    #[strum(serialize = "javascript")]
    JavaScript,
    /// Specifies the Lua Implementation language.
    Lua,
    /// Specifies the Objective-C Implementation language.
    ObjectiveC,
    /// Specifies the Perl Implementation language.
    Perl,
    /// Specifies the PHP Implementation language.
    Php,
    /// Specifies the Windows PowerShell Implementation language.
    #[strum(serialize = "powershell")]
    PowerShell,
    /// Specifies the Python Implementation language.
    Python,
    /// Specifies the Ruby Implementation language.
    Ruby,
    /// Specifies the Scala Implementation language.
    Scala,
    /// Specifies the Swift Implementation language.
    Swift,
    /// Specifies the TypeScript Implementation language.
    #[strum(serialize = "typescript")]
    TypeScript,
    /// Specifies the Visual Basic Implementation language.
    VisualBasic,
    /// Specifies the x86 32-bit Assembly Implementation language.
    X86_32,
    /// Specifies the x86 64-bit Assembly Implementation language.
    X86_64,
}

/// This is a non-exhaustive, open vocabulary that covers common pattern languages and is intended to characterize the pattern language that the indicator pattern is
/// expressed in within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum IndicatorPatternType {
    /// Specifies a pattern expressed as a Perl Compatible Regular Expression (PCRE).
    Pcre,
    /// Specifies a pattern expressed as a Sigma rule.
    Sigma,
    /// Specifies a pattern expressed as a Snort rule.
    Snort,
    /// Specifies a pattern expressed as a Suricata rule.
    Suricata,
    /// Specifies a pattern expressed in the STIX pattern language.
    Stix,
    /// Specifies a pattern expressed as a YARA rule.
    Yara,
}

///Indicator type is an open vocabulary used to categorize Indicators.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum IndicatorType {
    /// Unexpected or unusual activity that may indicate an attack or other malicious activity.
    AnomalousActivity,
    /// Traffic or activity related to anonymization, such as TOR, VPN, or proxies.
    Anonymization,
    /// Seemingly benign traffic or activity used in the context of analysis or testing.
    Benign,
    /// Traffic or activity believed to be the result of a compromise.
    Compromised,
    /// Traffic or activity believed to be representative of malicious activity.
    MaliciousActivity,
    /// Traffic or activity related to the attribution of an attack or other activity.
    Attribution,
    /// None of the other types apply, or the type is not known.
    Unknown,
}

/// Represents the type of infrastructure used in cyber attacks within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum InfrastructureType {
    /// Specifies infrastructure used for conducting amplification attacks.
    Amplification,
    /// Specific infrastructure used for anonymization, such as a proxy.
    Anonymization,
    /// Specifies the membership/makeup of a botnet, in terms of the network addresses of the hosts that comprise the botnet.
    Botnet,
    /// Specifies infrastructure used for command and control (C2). This is typically a domain name or IP address.
    CommandAndControl,
    /// Specifies infrastructure used as an endpoint for data exfiltration.
    Exfiltration,
    /// Specifies infrastructure used for hosting malware.
    HostingMalware,
    /// Specifies infrastructure used for hosting a list of targets for DDOS attacks, phishing, and other malicious activities. This is typically a domain name or IP address.
    HostingTargetLists,
    /// Specifies infrastructure used for conducting phishing attacks.
    Phishing,
    /// Specifies infrastructure used for conducting reconnaissance activities.
    Reconnaissance,
    /// Specifies infrastructure used for staging.
    Staging,
    /// Specifies an infrastructure of some undefined type.
    Undefined,
}

/// Represents different malware capabilities within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum MalwareCapability {
    /// Indicates the ability to access remote machines.
    AccessesRemoteMachines,
    /// Indicates the ability to prevent debugging or make it more difficult.
    AntiDebugging,
    /// Indicates the ability to prevent disassembly or make it more difficult.
    AntiDisassembly,
    /// Indicates the ability to prevent execution inside an emulator or make it more difficult.
    AntiEmulation,
    /// Indicates the ability to prevent or complicate memory forensics.
    AntiMemoryForensics,
    /// Indicates the ability to prevent sandbox-based analysis or make it more difficult.
    AntiSandbox,
    /// Indicates the ability to prevent VM-based analysis or make it more difficult.
    AntiVm,
    /// Indicates the ability to capture data from input peripherals, like keylogging.
    CapturesInputPeripherals,
    /// Indicates the ability to capture data from output peripherals, like screen scraping.
    CapturesOutputPeripherals,
    /// Indicates the ability to capture information about a system's state.
    CapturesSystemStateData,
    /// Indicates the ability to clean traces of infection from a system.
    CleansTracesOfInfection,
    /// Indicates the ability to commit fraud, such as click fraud.
    CommitsFraud,
    /// Indicates the ability to communicate with a command and control server.
    CommunicatesWithC2,
    /// Indicates the ability to compromise data availability.
    CompromisesDataAvailability,
    /// Indicates the ability to compromise data integrity.
    CompromisesDataIntegrity,
    /// Indicates the ability to consume system resources, compromising availability.
    CompromisesSystemAvailability,
    /// Indicates the ability to control the local machine.
    ControlsLocalMachine,
    /// Indicates the ability to bypass or disable security software.
    DegradesSecuritySoftware,
    /// Indicates the ability to disable system updates and patches.
    DegradesSystemUpdates,
    /// Indicates the ability to identify command and control servers.
    DeterminesC2Server,
    /// Indicates the ability to send spam email messages.
    EmailsSpam,
    /// Indicates the ability to escalate privileges.
    EscalatesPrivileges,
    /// Indicates the ability to evade antivirus detection.
    EvadesAv,
    /// Indicates the ability to exfiltrate data.
    ExfiltratesData,
    /// Indicates the ability to fingerprint the host system.
    FingerprintsHost,
    /// Indicates the ability to hide artifacts like files and open ports.
    HidesArtifacts,
    /// Indicates the ability to hide executing code.
    HidesExecutingCode,
    /// Indicates the ability to infect files on the system.
    InfectsFiles,
    /// Indicates the ability to infect remote machines.
    InfectsRemoteMachines,
    /// Indicates the ability to install additional components.
    InstallsOtherComponents,
    /// Indicates the ability to persist after a system reboot.
    PersistsAfterSystemReboot,
    /// Indicates the ability to prevent access to its artifacts.
    PreventsArtifactAccess,
    /// Indicates the ability to prevent deletion of its artifacts.
    PreventsArtifactDeletion,
    /// Indicates the ability to probe the network environment.
    ProbesNetworkEnvironment,
    /// Indicates the ability to modify itself.
    SelfModifies,
    /// Indicates the ability to steal authentication credentials.
    StealsAuthenticationCredentials,
    /// Indicates the ability to compromise system operational integrity.
    ViolatesSystemOperationalIntegrity,
}

/// Represents the common types of results from scanner or tool analysis process  within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum MalwareResult {
    /// The analysis determined that the sample is benign.
    Benign,
    /// The analysis determined that the sample is malicious.
    Malicious,
    /// The analysis determined that the sample is suspicious.
    Suspicious,
    /// The analysis could not determine a result.
    Unknown,
}

/// Represents the different types and functions of malware within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum MalwareType {
    /// Adware: Software funded by advertising, may gather sensitive user information.
    Adware,
    /// Backdoor: Allows an attacker to perform actions on a remote system.
    Backdoor,
    /// Bot: Resides on an infected system, part of a botnet, monitors a backdoor for instructions.
    Bot,
    /// Bootkit: Targets the Master Boot Record of the target computer.
    Bootkit,
    /// DDoS: Used to perform a distributed denial of service attack.
    Ddos,
    /// Downloader: A small trojan file programmed to download and execute other files.
    Downloader,
    /// Dropper: Deposits an enclosed payload (generally, other malware) onto the target computer.
    Dropper,
    /// ExploitKit: A software toolkit to target common vulnerabilities.
    ExploitKit,
    /// Keylogger: Monitors keystrokes and records them or sends them back to a central point.
    Keylogger,
    /// Ransomware: Encrypts files on a system, demanding ransom for access codes.
    Ransomware,
    /// RemoteAccessTrojan: A trojan capable of controlling a machine through remote commands.
    RemoteAccessTrojan,
    /// ResourceExploitation: Steals a system's resources, such as a malicious bitcoin miner.
    ResourceExploitation,
    /// RogueSecuritySoftware: A fake security product demanding money to clean phony infections.
    RogueSecuritySoftware,
    /// Rootkit: Hides its files or processes to conceal its presence and activities.
    Rootkit,
    /// ScreenCapture: Captures images from the target system's screen for exfiltration.
    ScreenCapture,
    /// Spyware: Gathers information on a user's system without their knowledge.
    Spyware,
    /// Trojan: Malicious program used to hack into a computer by misleading users.
    Trojan,
    /// Unknown: Not enough information to determine the type of malware.
    Unknown,
    /// Virus: Replicates by reproducing itself or infecting other programs.
    Virus,
    /// Webshell: Malicious script used to maintain persistent access on a compromised web application.
    Webshell,
    /// Wiper: Deletes files or entire disks on a machine.
    Wiper,
    /// Worm: Self-replicating program that executes itself without user intervention.
    Worm,
}

/// Represents the various types of opinions within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum OpinionType {
    /// A strongly agreeing opinion on the referenced object.
    StronglyAgree,
    /// An agreeing opinion on the referenced object.
    Agree,
    /// A neutral opinion on the referenced object.
    #[default]
    Neutral,
    /// A disagreeing opinion on the referenced object.
    Disagree,
    /// A strongly disagreeing opinion on the referenced object.
    StronglyDisagree,
}

// The members of the region ov open vocabulary
// Mimics python stix region
/// Represents the world regions based on the United Nations geoscheme within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum Region {
    /// The continent of Africa.
    Africa,
    /// The Eastern Africa sub-region.
    EasternAfrica,
    /// The Middle Africa sub-region.
    MiddleAfrica,
    /// The Northern Africa sub-region.
    NorthernAfrica,
    /// The Southern Africa sub-region.
    SouthernAfrica,
    /// The Western Africa sub-region.
    WesternAfrica,
    /// The Americas region.
    Americas,
    /// The Latin America and the Caribbean sub-region.
    LatinAmericaCaribbean,
    /// The South America sub-region.
    SouthAmerica,
    /// The Caribbean sub-region.
    Caribbean,
    /// The Central America sub-region.
    CentralAmerica,
    /// The Northern America sub-region.
    NorthernAmerica,
    /// The continent of Asia.
    Asia,
    /// The Central Asia sub-region.
    CentralAsia,
    /// The Eastern Asia sub-region.
    EasternAsia,
    /// The Southern Asia sub-region.
    SouthernAsia,
    /// The South-Eastern Asia sub-region.
    SouthEasternAsia,
    /// The Western Asia sub-region.
    WesternAsia,
    /// The continent of Europe.
    Europe,
    /// The Eastern Europe sub-region.
    EasternEurope,
    /// The Northern Europe sub-region.
    NorthernEurope,
    /// The Southern Europe sub-region.
    SouthernEurope,
    /// The Western Europe sub-region.
    WesternEurope,
    /// The continent of Oceania.
    Oceania,
    /// The continent of Antarctica.
    Antarctica,
    /// The Australia and New Zealand sub-region.
    AustraliaNewZealand,
    /// The Melanesia sub-region.
    Melanesia,
    /// The Micronesia sub-region.
    Micronesia,
    /// The Polynesia sub-region.
    Polynesia,
}

/// Represents the various types of reports within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum ReportType {
    /// A report about an attack pattern, or a report consisting of an attack pattern.
    AttackPattern,
    /// A report about a campaign, or a report consisting of a campaign.
    Campaign,
    /// A report about an identity, or a report consisting of an identity.
    Identity,
    /// A report consisting of a set of indicators.
    Indicator,
    /// A report about an intrusion set, or a report consisting of an intrusion set.
    IntrusionSet,
    /// A report consisting of malware and malware analysis objects.
    Malware,
    /// A report consisting of observed data.
    ObservedData,
    /// A report about a threat actor, or a report consisting of a threat actor.
    ThreatActor,
    /// A report about a threat that is not specific to one of the other values.
    ThreatReport,
    /// A report consisting of tool objects.
    Tool,
    /// A report about a vulnerability, or a report consisting of a vulnerability.
    Vulnerability,
}

/// Represents the various roles of threat actors within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum ThreatActorRole {
    /// Threat actor executes attacks either on behalf of themselves or at the direction of someone else.
    Agent,
    /// The threat actor who directs the activities, goals, and objectives of the malicious activities.
    Director,
    /// A threat actor acting by themselves.
    Independent,
    /// Someone who designs the battle space.
    InfrastructureArchitect,
    /// The threat actor who provides and supports the attack infrastructure.
    InfrastructureOperator,
    /// The threat actor who authors malware or other malicious tools.
    MalwareAuthor,
    /// The threat actor who funds the malicious activities.
    Sponsor,
}

/// Represents the various levels of threat actor sophistication within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum ThreatActorSophistication {
    /// Can develop their own tools or scripts from known vulnerabilities.
    Advanced,
    /// Can focus on the discovery and use of unknown malicious code.
    Expert,
    /// Highly technical and proficient, capable of discovering new vulnerabilities.
    Innovator,
    /// Can proficiently use existing attack frameworks and toolkits.
    Intermediate,
    /// Can carry out random acts of disruption using tools they do not understand.
    None,
    /// Can minimally use existing techniques and programs to exploit weaknesses.
    Minimal,
    /// State actors creating vulnerabilities through influence in supply chains.
    Strategic,
}

/// Represents the various types of threat actors within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum ThreatActorType {
    /// Highly motivated supporter of a social or political cause, potentially disruptive.
    Activist,
    /// An organization competing in the same economic marketplace, seeking advantage.
    Competitor,
    /// An enterprise organized for large-scale criminal activity for profit.
    CrimeSyndicate,
    /// Individual committing computer crimes for personal financial gain.
    Criminal,
    /// An individual breaking into networks for thrill or challenge.
    Hacker,
    /// A non-hostile insider unintentionally exposing the organization to harm.
    InsiderAccidental,
    /// Current or former insiders seeking revenge for perceived wrongs.
    InsiderDisgruntled,
    /// Entities working for or directed by a nation state, with significant resources.
    NationState,
    /// Seeks to cause embarrassment and brand damage by exposing sensitive information.
    Sensationalist,
    /// Secretly collects sensitive information for use, dissemination, or sale.
    Spy,
    /// Uses extreme violence to advance a social or political agenda.
    Terrorist,
    /// Insufficient information to determine the type of threat actor.
    Unknown,
}

/// Represents the various ToolType of threat actors within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter, Default)]
#[strum(serialize_all = "kebab-case")]
pub enum ToolType {
    /// Tools used to collect, crack, or exploit credentials, such as password crackers or keyloggers.
    CredentialExploitation,
    /// Tools used to perform denial-of-service attacks or exhaust resources.
    DenialOfService,
    /// Tools used to exploit vulnerabilities in software or systems, such as exploit kits.
    Exploitation,
    /// Tools used to gather information about targets, networks, services, or users.
    InformationGathering,
    /// Tools used to capture network traffic, such as sniffers.
    NetworkCapture,
    /// Tools used to access hosts, services, or networks remotely, such as remote access trojans.
    RemoteAccess,
    /// Tools used to scan hosts or networks for vulnerabilities, services, or configurations.
    VulnerabilityScanning,
    /// None of the other types apply, or the type is not known.
    #[default]
    Unknown,
}
