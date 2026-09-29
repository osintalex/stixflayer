use crate::{
    base::Stix,
    common::validation::{is_valid_hex, validate_refs_are_type},
    error::{add_error, return_multiple_errors, StixError as Error},
    types::{Hashes, Identifier, StixDictionary, Timestamp},
};
use ordered_float::OrderedFloat as ordered_float;
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_opt_i64;
use serde_this_or_that::as_opt_u64;
use serde_with::skip_serializing_none;
use strum::{AsRefStr, EnumIter};

/// Possible extensions for File SCOs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, AsRefStr, EnumIter)]
#[serde(untagged)]
#[strum(serialize_all = "kebab-case")]
pub enum FileExtensions {
    ArchiveExt(ArchiveExtension),
    NtfsExt(NtfsExtension),
    PdfExt(PdfExtension),
    RasterExt(RasterExtension),
    WindowsPebinaryExt(Box<WindowsPebinaryExtension>),
}

impl Stix for FileExtensions {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
    }
}

/// Archive File Extension
///
/// The Archive File extension specifies a default extension for capturing properties
/// specific to archive files. The key for this extension when used in the extensions
/// dictionary **MUST** be archive-ext.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_xi3g7dwaigs6>
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveExtension {
    /// This property specifies the files that are contained in the archive. It MUST contain references to one or more File objects.
    pub contains_refs: Vec<Identifier>,
    /// Specifies a comment included as part of the archive file.
    pub comment: Option<String>,
}

impl Stix for ArchiveExtension {
    fn stix_check(&self) -> Result<(), Error> {
        validate_refs_are_type(&self.contains_refs, &["file"], "contains_refs")
    }
}
///  NFTS Extension
///
/// The NTFS file extension specifies a default extension for capturing properties
/// specific to the storage of the file on the NTFS file system. The key for this
/// extension when used in the extensions dictionary **MUST** be ntfs-ext.
///
/// An object using the NTFS File Extension **MUST** contain at least one property from this extension.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_o6cweepfrsci>
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NtfsExtension {
    /// Specifies the security ID (SID) value assigned to the file.
    pub sid: Option<String>,
    /// Specifies a list of NTFS alternate data streams that exist for the file.
    pub alternate_data_streams: Option<Vec<AlternateDataStreamType>>,
}

impl Stix for NtfsExtension {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();
        if self.sid.is_none() && self.alternate_data_streams.is_none() {
            errors.push(Error::ValidationError(
                "at least one property must be set".to_string(),
            ));
        }
        if let Some(alternate_data_streams) = &self.alternate_data_streams {
            add_error(&mut errors, alternate_data_streams.stix_check());
        }
        return_multiple_errors(errors)
    }
}

///  Alternate Data Stream Type
///
/// The Alternate Data Stream type represents an
/// NTFS alternate data stream.
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlternateDataStreamType {
    /// Specifies the name of the alternate data stream.
    pub name: String,
    /// Specifies a dictionary of hashes for the data contained in the alternate data stream.
    pub hashes: Option<Hashes>,
    /// Specifies the size of the alternate data stream, in bytes. The value of this property MUST NOT be negative.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size: Option<u64>,
}

impl Stix for AlternateDataStreamType {
    fn stix_check(&self) -> Result<(), Error> {
        if let Some(hashes) = &self.hashes {
            hashes.stix_check()?;
        }
        if let Some(size) = &self.size {
            size.stix_check()
        } else {
            Ok(())
        }
    }
}

///  PDF File Extension
///
/// The PDF file extension specifies a default extension for capturing properties specific to PDF files.
/// The key for this extension when used in the extensions dictionary **MUST** be pdf-ext.
///
/// An object using the PDF File Extension **MUST** contain at least one property from this extension.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_8xmpb2ghp9km>
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfExtension {
    /// Specifies the decimal version number of the string from the PDF header that specifies the version of the PDF specification to which the PDF file conforms. E.g., 1.4.
    pub version: Option<String>,
    /// Specifies whether the PDF file has been optimized.
    pub is_optimized: Option<bool>,
    /// Specifies details of the PDF document information dictionary (DID), which includes properties like the document creation data and producer, as a dictionary.
    pub document_info_dict: Option<StixDictionary<String>>,
    /// Specifies the first file identifier found for the PDF file.
    pub pdfid0: Option<String>,
    /// Specifies the second file identifier found for the PDF file.
    pub pdfid1: Option<String>,
}

impl Stix for PdfExtension {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if self.version.is_none()
            && self.is_optimized.is_none()
            && self.document_info_dict.is_none()
            && self.pdfid0.is_none()
            && self.pdfid1.is_none()
        {
            errors.push(Error::ValidationError(
                "At least one property must be set".to_string(),
            ));
        }
        if let Some(document_info_dict) = &self.document_info_dict {
            add_error(&mut errors, document_info_dict.stix_check());
            const VALID_DID_KEYS: &[&str] = &[
                "Title",
                "Author",
                "Subject",
                "Keywords",
                "Creator",
                "Producer",
                "CreationDate",
                "ModDate",
                "Trapped",
            ];
            for key in document_info_dict.keys() {
                if !VALID_DID_KEYS.contains(&key.as_str()) {
                    errors.push(Error::ValidationError(format!(
                        "PDF document_info_dict key '{}' is not a valid PDF Document Information Dictionary key.",
                        key,
                    )));
                }
            }
        }

        return_multiple_errors(errors)
    }
}

///  Raster Image File Extension
///  
/// The Raster Image file extension specifies a default extension for
/// capturing properties specific to raster image files. The key for this
/// extension when used in the extensions dictionary **MUST** be raster-image-ext.
///
/// An object using the Raster Image File Extension **MUST** contain at least one property from this extension.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_u5z7i2ox8w4x>
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RasterExtension {
    /// Specifies the height of the image in the image file, in pixels.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub image_height: Option<i64>,
    /// Specifies the width of the image in the image file, in pixels.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub image_width: Option<i64>,
    /// Specifies the sum of bits used for each color channel in the image file, and thus the total number of pixels used for expressing the color depth of the image.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub bits_per_pixel: Option<i64>,
    /// Specifies the set of EXIF tags found in the image file, as a dictionary. Each key/value pair in the dictionary represents the name/value of a single EXIF tag.
    pub exif_tags: Option<StixDictionary<ExifTag>>,
}

impl Stix for RasterExtension {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if self.image_height.is_none()
            && self.image_width.is_none()
            && self.bits_per_pixel.is_none()
            && self.exif_tags.is_none()
        {
            errors.push(Error::ValidationError(
                "At least one property must be set".to_string(),
            ));
        }
        if let Some(image_height) = &self.image_height {
            add_error(&mut errors, image_height.stix_check());
        }
        if let Some(image_width) = &self.image_width {
            add_error(&mut errors, image_width.stix_check());
        }
        if let Some(bits_per_pixel) = &self.bits_per_pixel {
            add_error(&mut errors, bits_per_pixel.stix_check());
        }
        if let Some(exif_tags) = &self.exif_tags {
            add_error(&mut errors, exif_tags.stix_check());
        }

        return_multiple_errors(errors)
    }
}

/// An EXIF tag, which can be either a string or an integer representing EXIF metadata fields
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExifTag {
    String(String),
    Integer(i64),
}
impl Stix for ExifTag {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
    }
}

///  Windows PE Binary File Extension
///
/// The Windows™ PE Binary File extension specifies a default extension for capturing properties
/// specific to Windows portable executable (PE) files. The key for this extension when used in the
/// extensions dictionary **MUST** be windows-pebinary-ext.
///
/// An object using the Windows™ PE Binary File Extension **MUST** contain at least one property
/// other than the required pe_type property from this extension.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_gg5zibddf9bs>
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPebinaryExtension {
    /// Specifies the type of the PE binary. This is an open vocabulary and values SHOULD come from the windows-pebinary-type-ov open vocabulary.
    pub pe_type: WindowsPebinaryTypeOv,
    /// Specifies the special import hash, or ‘imphash’, calculated for the PE Binary based on its imported libraries and functions.
    pub imphash: Option<String>,
    /// Specifies the type of target machine.
    pub machine_hex: Option<String>,
    /// Specifies the number of sections in the PE binary, as a non-negative integer.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub number_of_sections: Option<u64>,
    /// Specifies the time when the PE binary was created. The timestamp value MUST be precise to the second.
    pub time_date_stamp: Option<Timestamp>,
    /// Specifies the file offset of the COFF symbol table.
    pub pointer_to_symbol_table_hex: Option<String>,
    /// Specifies the number of entries in the symbol table of the PE binary, as a non-negative integer.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub number_of_symbols: Option<u64>,
    /// Specifies the size of the optional header of the PE binary. The value of this property MUST NOT be negative.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size_of_optional_header: Option<u64>,
    /// Specifies the flags that indicate the file’s characteristics.
    pub characteristics_hex: Option<String>,
    /// Specifies any hashes that were computed for the file header.
    pub file_header_hashes: Option<Hashes>,
    /// Specifies the PE optional header of the PE binary
    pub optional_header: Option<WindowsPEOptionalHeaderType>,
    /// Specifies metadata about the sections in the PE file.
    pub sections: Option<Vec<WindowsPESectionType>>,
}

impl Stix for WindowsPebinaryExtension {
    fn stix_check(&self) -> Result<(), Error> {
        if let Some(file_header_hashes) = &self.file_header_hashes {
            file_header_hashes.stix_check()?;
        }
        let mut errors = Vec::new();
        if let Some(characteristics_hex) = &self.characteristics_hex {
            if !is_valid_hex(characteristics_hex) {
                errors.push(Error::ParseHexError(
                    "characteristics_hex -- ".to_string() + characteristics_hex,
                ))
            }
        }
        if let Some(machine_hex) = &self.machine_hex {
            if !is_valid_hex(machine_hex) {
                errors.push(Error::ParseHexError(
                    "machine_hex -- ".to_string() + machine_hex,
                ))
            }
        }
        if let Some(number_of_sections) = &self.number_of_sections {
            add_error(&mut errors, number_of_sections.stix_check());
        }
        if let Some(number_of_symbols) = &self.number_of_symbols {
            add_error(&mut errors, number_of_symbols.stix_check());
        }
        if let Some(pointer_to_symbol_table_hex) = &self.pointer_to_symbol_table_hex {
            if !is_valid_hex(pointer_to_symbol_table_hex) {
                errors.push(Error::ParseHexError(
                    "pointer_to_symbol_table_hex -- ".to_string() + pointer_to_symbol_table_hex,
                ))
            }
        }
        if let Some(size_of_optional_header) = &self.size_of_optional_header {
            add_error(&mut errors, size_of_optional_header.stix_check());
        }
        if let Some(optional_header) = &self.optional_header {
            add_error(&mut errors, optional_header.stix_check());
        }
        if let Some(sections) = &self.sections {
            add_error(&mut errors, sections.stix_check());
        }

        if self.imphash.is_none()
            && self.machine_hex.is_none()
            && self.number_of_sections.is_none()
            && self.time_date_stamp.is_none()
            && self.pointer_to_symbol_table_hex.is_none()
            && self.number_of_symbols.is_none()
            && self.size_of_optional_header.is_none()
            && self.characteristics_hex.is_none()
            && self.file_header_hashes.is_none()
            && self.optional_header.is_none()
            && self.sections.is_none()
        {
            errors.push(Error::ValidationError(
                "At least one property must be set".to_string(),
            ));
        }

        return_multiple_errors(errors)
    }
}

/// Possible types of a Windows PE binary, specifying a file extension for capturing properties specific to Windows portable executable (PE) files
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize, AsRefStr, EnumIter)]
pub enum WindowsPebinaryTypeOv {
    Dll,
    #[default]
    Exe,
    Sys,
    Other(String),
}
///  Windows™ PE Optional Header Type
///
/// The Windows PE Optional Header
/// type represents the properties of the PE optional header.
/// An object using the Windows PE Optional Header Type **MUST** contain at least one property from this type.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_29l09w731pzc>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPEOptionalHeaderType {
    /// Specifies the hex value that indicates the type of the PE binary.
    pub magic_hex: Option<String>,
    /// Specifies the linker major version number.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub major_linker_version: Option<i64>,
    /// Specifies the linker minor version number.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub minor_linker_version: Option<i64>,
    /// Specifies the size of the code (text) section. If there are multiple such sections, this refers to the sum of the sizes of each section.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size_of_code: Option<u64>,
    /// Specifies the size of the initialized data section. If there are multiple such sections, this refers to the sum of the sizes of each section.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size_of_initialized_data: Option<u64>,
    /// Specifies the size of the uninitialized data section. If there are multiple such sections, this refers to the sum of the sizes of each section.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size_of_uninitialized_data: Option<u64>,
    /// Specifies the address of the entry point relative to the image base when the executable is loaded into memory.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub address_of_entry_point: Option<i64>,
    /// Specifies the address that is relative to the image base of the beginning-of-code section when it is loaded into memory.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub base_of_code: Option<i64>,
    /// Specifies the address that is relative to the image base of the beginning-of-data section when it is loaded into memory.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub base_of_data: Option<i64>,
    /// Specifies the preferred address of the first byte of the image when loaded into memory.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub image_base: Option<i64>,
    /// Specifies the alignment (in bytes) of PE sections when they are loaded into memory.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub section_alignment: Option<i64>,
    /// Specifies the factor (in bytes) that is used to align the raw data of sections in the image file.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub file_alignment: Option<i64>,
    /// Specifies the major version number of the required operating system.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub major_os_version: Option<i64>,
    /// Specifies the minor version number of the required operating system.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub minor_os_version: Option<i64>,
    /// Specifies the major version number of the image.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub major_image_version: Option<i64>,
    /// Specifies the minor version number of the image.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub minor_image_version: Option<i64>,
    /// Specifies the major version number of the subsystem.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub major_subsystem_version: Option<i64>,
    /// Specifies the minor version number of the subsystem.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub minor_subsystem_version: Option<i64>,
    /// Specifies the reserved win32 version value.
    pub win32_version_value_hex: Option<String>,
    /// Specifies the size of the image in bytes, including all headers, as the image is loaded in memory.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size_of_image: Option<u64>,
    /// Specifies the size of the image in bytes, including all headers, as the image is loaded in memory.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size_of_headers: Option<u64>,
    /// Specifies the checksum of the PE binary.
    pub checksum_hex: Option<String>,
    /// Specifies the subsystem (e.g., GUI, device driver, etc.) that is required to run this image.
    pub subsystem_hex: Option<String>,
    /// Specifies the flags that characterize the PE binary.
    pub dll_characteristics_hex: Option<String>,
    /// Specifies the size of the stack to reserve, in bytes
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size_of_stack_reserve: Option<u64>,
    /// Specifies the size of the stack to commit, in bytes.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size_of_stack_commit: Option<u64>,
    /// Specifies the size of the local heap space to reserve, in bytes.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size_of_heap_reserve: Option<u64>,
    /// Specifies the size of the local heap space to commit, in bytes.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size_of_heap_commit: Option<u64>,
    /// Specifies the reserved loader flags.
    pub loader_flags_hex: Option<String>,
    /// Specifies the number of data-directory entries in the remainder of the optional header.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub number_of_rva_and_sizes: Option<i64>,
    /// Specifies any hashes that were computed for the optional header.
    pub hashes: Option<Hashes>,
}

impl Stix for WindowsPEOptionalHeaderType {
    fn stix_check(&self) -> Result<(), Error> {
        if let Some(hashes) = &self.hashes {
            hashes.stix_check()?;
        }
        let mut errors = Vec::new();

        if let Some(size_of_code) = &self.size_of_code {
            add_error(&mut errors, size_of_code.stix_check());
        }
        if let Some(size_of_initialized_data) = &self.size_of_initialized_data {
            add_error(&mut errors, size_of_initialized_data.stix_check());
        }
        if let Some(size_of_uninitialized_data) = &self.size_of_uninitialized_data {
            add_error(&mut errors, size_of_uninitialized_data.stix_check());
        }
        if let Some(size_of_image) = &self.size_of_image {
            add_error(&mut errors, size_of_image.stix_check());
        }
        if let Some(size_of_headers) = &self.size_of_headers {
            add_error(&mut errors, size_of_headers.stix_check());
        }
        if let Some(size_of_stack_reserve) = &self.size_of_stack_reserve {
            add_error(&mut errors, size_of_stack_reserve.stix_check());
        }
        if let Some(size_of_stack_commit) = &self.size_of_stack_commit {
            add_error(&mut errors, size_of_stack_commit.stix_check());
        }
        if let Some(size_of_heap_reserve) = &self.size_of_heap_reserve {
            add_error(&mut errors, size_of_heap_reserve.stix_check());
        }
        if let Some(size_of_heap_commit) = &self.size_of_heap_commit {
            add_error(&mut errors, size_of_heap_commit.stix_check());
        }

        if let Some(magic_hex) = &self.magic_hex {
            if !is_valid_hex(magic_hex) {
                errors.push(Error::ParseHexError(
                    "magic_hex -- ".to_string() + magic_hex,
                ))
            }
        }
        if let Some(major_linker_version) = &self.major_linker_version {
            add_error(&mut errors, major_linker_version.stix_check());
        }
        if let Some(minor_linker_version) = &self.minor_linker_version {
            add_error(&mut errors, minor_linker_version.stix_check());
        }
        if let Some(address_of_entry_point) = &self.address_of_entry_point {
            add_error(&mut errors, address_of_entry_point.stix_check());
        }
        if let Some(base_of_code) = &self.base_of_code {
            add_error(&mut errors, base_of_code.stix_check());
        }
        if let Some(base_of_data) = &self.base_of_data {
            add_error(&mut errors, base_of_data.stix_check());
        }
        if let Some(image_base) = &self.image_base {
            add_error(&mut errors, image_base.stix_check());
        }
        if let Some(section_alignment) = &self.section_alignment {
            add_error(&mut errors, section_alignment.stix_check());
        }
        if let Some(file_alignment) = &self.file_alignment {
            add_error(&mut errors, file_alignment.stix_check());
        }
        if let Some(major_os_version) = &self.major_os_version {
            add_error(&mut errors, major_os_version.stix_check());
        }
        if let Some(minor_os_version) = &self.minor_os_version {
            add_error(&mut errors, minor_os_version.stix_check());
        }
        if let Some(major_image_version) = &self.major_image_version {
            add_error(&mut errors, major_image_version.stix_check());
        }
        if let Some(minor_image_version) = &self.minor_image_version {
            add_error(&mut errors, minor_image_version.stix_check());
        }
        if let Some(major_subsystem_version) = &self.major_subsystem_version {
            add_error(&mut errors, major_subsystem_version.stix_check());
        }
        if let Some(minor_subsystem_version) = &self.minor_subsystem_version {
            add_error(&mut errors, minor_subsystem_version.stix_check());
        }
        if let Some(win32_version_value_hex) = &self.win32_version_value_hex {
            if !is_valid_hex(win32_version_value_hex) {
                errors.push(Error::ParseHexError(
                    "win32_version_value_hex -- ".to_string() + win32_version_value_hex,
                ))
            }
        }
        if let Some(checksum_hex) = &self.checksum_hex {
            if !is_valid_hex(checksum_hex) {
                errors.push(Error::ParseHexError(
                    "checksum_hex -- ".to_string() + checksum_hex,
                ))
            }
        }
        if let Some(subsystem_hex) = &self.subsystem_hex {
            if !is_valid_hex(subsystem_hex) {
                errors.push(Error::ParseHexError(
                    "subsystem_hex -- ".to_string() + subsystem_hex,
                ))
            }
        }
        if let Some(dll_characteristics_hex) = &self.dll_characteristics_hex {
            if !is_valid_hex(dll_characteristics_hex) {
                errors.push(Error::ParseHexError(
                    "dll_characteristics_hex -- ".to_string() + dll_characteristics_hex,
                ))
            }
        }
        if let Some(loader_flags_hex) = &self.loader_flags_hex {
            if !is_valid_hex(loader_flags_hex) {
                errors.push(Error::ParseHexError(
                    "loader_flags_hex -- ".to_string() + loader_flags_hex,
                ))
            }
        }
        if let Some(number_of_rva_and_sizes) = &self.number_of_rva_and_sizes {
            add_error(&mut errors, number_of_rva_and_sizes.stix_check());
        }
        if self.magic_hex.is_none()
            && self.major_linker_version.is_none()
            && self.minor_linker_version.is_none()
            && self.size_of_code.is_none()
            && self.size_of_initialized_data.is_none()
            && self.size_of_uninitialized_data.is_none()
            && self.address_of_entry_point.is_none()
            && self.base_of_code.is_none()
            && self.base_of_data.is_none()
            && self.image_base.is_none()
            && self.section_alignment.is_none()
            && self.file_alignment.is_none()
            && self.major_os_version.is_none()
            && self.minor_os_version.is_none()
            && self.major_image_version.is_none()
            && self.minor_image_version.is_none()
            && self.major_subsystem_version.is_none()
            && self.minor_subsystem_version.is_none()
            && self.win32_version_value_hex.is_none()
            && self.size_of_image.is_none()
            && self.size_of_headers.is_none()
            && self.checksum_hex.is_none()
            && self.subsystem_hex.is_none()
            && self.dll_characteristics_hex.is_none()
            && self.size_of_stack_reserve.is_none()
            && self.size_of_stack_commit.is_none()
            && self.size_of_heap_commit.is_none()
            && self.size_of_heap_reserve.is_none()
            && self.loader_flags_hex.is_none()
            && self.number_of_rva_and_sizes.is_none()
            && self.hashes.is_none()
        {
            errors.push(Error::ValidationError(
                "At least one property must be set".to_string(),
            ));
        }

        return_multiple_errors(errors)
    }
}

///  Windows™ PE Section Type
/// The Windows PE Section type specifies metadata about a PE file section
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ioapwyd8oimw>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPESectionType {
    /// Specifies the name of the section.
    pub name: String,
    /// Specifies the size of the section, in bytes.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size: Option<u64>,
    /// Specifies the calculated entropy for the section, as calculated using the Shannon algorithm <https://en.wiktionary.org/wiki/Shannon_entropy>. The size of each input character is defined as a byte, resulting in a possible range of 0 through 8.
    pub entropy: Option<ordered_float<f32>>,
    /// Specifies any hashes computed over the section.
    pub hashes: Option<Hashes>,
}

impl Stix for WindowsPESectionType {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(size) = &self.size {
            add_error(&mut errors, size.stix_check());
        }
        if let Some(hashes) = &self.hashes {
            add_error(&mut errors, hashes.stix_check());
        }

        return_multiple_errors(errors)
    }
}
