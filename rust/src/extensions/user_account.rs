use crate::{
    base::Stix,
    error::StixError as Error,
};
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_opt_i64;
use serde_with::skip_serializing_none;
use strum::{AsRefStr, EnumIter};

/// Possible extensions for UserAccount SCOs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, AsRefStr, EnumIter)]
#[serde(untagged)]
#[strum(serialize_all = "kebab-case")]
pub enum UserAccountExtensions {
    UnixAccountExt(UnixAccountExtension),
}

/// The UNIX account extension specifies a default extension for capturing the additional information for an account on a UNIX system.
///
/// An object using the UNIX Account Extension **MUST** contain at least one property from this extension.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_hodiamlggpw5>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnixAccountExtension {
    /// Specifies the primary group ID of the account.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub gid: Option<i64>,
    /// Specifies a list of names of groups that the account is a member of.
    pub groups: Option<Vec<String>>,
    /// Specifies the home directory of the account.
    pub home_dir: Option<String>,
    /// Specifies the account’s command shell.
    pub shell: Option<String>,
}

impl Stix for UnixAccountExtension {
    fn stix_check(&self) -> Result<(), Error> {
        if self.gid.is_none()
            && self.groups.is_none()
            && self.home_dir.is_none()
            && self.shell.is_none()
        {
            return Err(Error::ValidationError(
                "At least one field must be set in UnixAccountExtension".to_string(),
            ));
        }
        if let Some(gid) = &self.gid {
            gid.stix_check()?;
        }
        Ok(())
    }
}
