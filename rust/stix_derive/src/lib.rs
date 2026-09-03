//! Derive macro for STIX property registries.
//!
//! `#[derive(StixProperties)]` generates a static list of the JSON property
//! names a STIX type accepts, and which of them are required. The trait and
//! types it references live in the main crate at
//! `::stixflayer::properties` (a proc-macro crate may only export
//! proc-macro functions).
//!
//! - On structs: generates `KNOWN`/`REQUIRED` impl consts derived from the
//!   struct's fields. `Option<T>` fields and fields with `#[serde(default)]`
//!   are optional. Field-level `#[serde(rename)]` and container-level
//!   `#[serde(rename_all)]` are honored. `#[serde(flatten)]`, `#[serde(skip)]`
//!   and `#[serde(skip_deserializing)]` fields are excluded from the struct's
//!   own lists (flattened data is composed at lookup time).
//!
//! - On newtype enums with `#[serde(tag = "...")]`: generates a
//!   `pub const <ENUM>_VARIANTS: &'static [VariantProps]` table mapping each
//!   variant's serialized tag name to its inner type's property lists. The
//!   inner types must themselves derive `StixProperties`. Variant-level
//!   `#[serde(rename)]` and `#[serde(alias)]` are honored.

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input, Data, DataEnum, DeriveInput, GenericArgument, Ident, PathArguments, Token,
};

#[proc_macro_derive(StixProperties)]
pub fn derive_stix_properties(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let result = match &input.data {
        Data::Struct(data) => derive_struct(&input.ident, &input.attrs, &data.fields),
        Data::Enum(data) => derive_enum(&input.ident, &input.attrs, data),
        Data::Union(_) => Err(syn::Error::new(
            input.ident.span(),
            "StixProperties cannot be derived for unions",
        )),
    };
    result.unwrap_or_else(|e| e.to_compile_error()).into()
}

#[derive(Default)]
struct SerdeAttrs {
    rename: Option<String>,
    alias: Vec<String>,
    default: bool,
    flatten: bool,
    skip: bool,
    skip_deserializing: bool,
    tag: Option<String>,
    rename_all: Option<String>,
}

fn parse_serde_attrs(attrs: &[syn::Attribute]) -> syn::Result<SerdeAttrs> {
    let mut out = SerdeAttrs::default();
    for attr in attrs {
        if !attr.path().is_ident("serde") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename") {
                out.rename = Some(meta.value()?.parse::<syn::LitStr>()?.value());
            } else if meta.path.is_ident("alias") {
                out.alias
                    .push(meta.value()?.parse::<syn::LitStr>()?.value());
            } else if meta.path.is_ident("default") {
                out.default = true;
            } else if meta.path.is_ident("flatten") {
                out.flatten = true;
            } else if meta.path.is_ident("skip") {
                out.skip = true;
            } else if meta.path.is_ident("skip_deserializing") {
                out.skip_deserializing = true;
            } else if meta.path.is_ident("tag") {
                out.tag = Some(meta.value()?.parse::<syn::LitStr>()?.value());
            } else if meta.path.is_ident("rename_all") {
                out.rename_all = Some(meta.value()?.parse::<syn::LitStr>()?.value());
            }
            // All other serde attributes (skip_serializing_if, deserialize_with, ...)
            // do not affect the registry and are ignored, but their arguments
            // must be consumed or parse_nested_meta errors.
            if meta.input.peek(Token![=]) {
                meta.value()?.parse::<syn::Lit>()?;
            } else if meta.input.peek(syn::token::Paren) {
                let group: proc_macro2::Group = meta.input.parse()?;
                debug_assert_eq!(group.delimiter(), proc_macro2::Delimiter::Parenthesis);
            }
            Ok(())
        })?;
    }
    Ok(out)
}

fn convert_case(ident: &str, style: &str) -> syn::Result<String> {
    match style {
        "snake_case" => Ok(ident.to_string()),
        "lowercase" => Ok(ident.to_ascii_lowercase()),
        "kebab-case" => Ok(stix_kebab(ident)),
        other => Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            format!("StixProperties: unsupported serde rename_all style `{other}`"),
        )),
    }
}

/// Kebab-case mirroring the main crate's `stix_case()` (types.rs): hyphen
/// before an uppercase character that follows a lowercase or digit, so word
/// boundaries split but digit boundaries do not (`ipv4-addr`,
/// `x509-certificate`).
fn stix_kebab(name: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = name.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if *c == '_' {
            out.push('-');
            continue;
        }
        if i > 0 && c.is_ascii_uppercase() {
            let prev = chars[i - 1];
            if prev.is_ascii_lowercase() || prev.is_ascii_digit() {
                out.push('-');
            }
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

fn is_option(ty: &syn::Type) -> bool {
    let syn::Type::Path(tp) = ty else {
        return false;
    };
    tp.path
        .segments
        .last()
        .is_some_and(|seg| seg.ident == "Option")
}

fn strip_box(ty: &syn::Type) -> syn::Result<&syn::Type> {
    let syn::Type::Path(tp) = ty else {
        return Ok(ty);
    };
    let Some(seg) = tp.path.segments.last() else {
        return Ok(ty);
    };
    if seg.ident != "Box" {
        return Ok(ty);
    }
    let PathArguments::AngleBracketed(args) = &seg.arguments else {
        return Err(syn::Error::new_spanned(
            ty,
            "StixProperties: Box<> with unexpected arguments",
        ));
    };
    match args.args.first() {
        Some(GenericArgument::Type(inner)) => Ok(inner),
        _ => Err(syn::Error::new_spanned(
            ty,
            "StixProperties: Box<> with no type argument",
        )),
    }
}

/// `DomainObjectType` -> `DOMAIN_OBJECT_TYPE`
fn screaming_case(name: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = name.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && c.is_ascii_uppercase() {
            let prev = chars[i - 1];
            if prev.is_ascii_lowercase() || prev.is_ascii_digit() {
                out.push('_');
            }
        }
        out.push(c.to_ascii_uppercase());
    }
    out
}

fn derive_struct(
    ident: &Ident,
    attrs: &[syn::Attribute],
    fields: &syn::Fields,
) -> syn::Result<proc_macro2::TokenStream> {
    let container = parse_serde_attrs(attrs)?;
    let named = match fields {
        syn::Fields::Named(named) => &named.named,
        _ => {
            return Err(syn::Error::new(
                ident.span(),
                "StixProperties requires structs with named fields",
            ))
        }
    };

    let mut known: Vec<syn::LitStr> = Vec::new();
    let mut required: Vec<syn::LitStr> = Vec::new();
    for field in named {
        let field_attrs = parse_serde_attrs(&field.attrs)?;
        // Flattened data is composed at lookup time; skipped fields are not
        // (de)serialized at all and so are not part of the registry.
        if field_attrs.flatten || field_attrs.skip || field_attrs.skip_deserializing {
            continue;
        }
        let field_ident = field
            .ident
            .as_ref()
            .expect("named field without identifier")
            .to_string();
        let json_name = match &field_attrs.rename {
            Some(r) => r.clone(),
            None => match &container.rename_all {
                Some(style) => convert_case(&field_ident, style)?,
                None => field_ident,
            },
        };
        let json_lit = syn::LitStr::new(&json_name, proc_macro2::Span::call_site());
        if !is_option(&field.ty) && !field_attrs.default {
            required.push(json_lit.clone());
        }
        known.push(json_lit);
    }

    Ok(quote! {
        impl crate::properties::StixProperties for #ident {
            const KNOWN: &'static [&'static str] = &[#(#known),*];
            const REQUIRED: &'static [&'static str] = &[#(#required),*];
        }
    })
}

fn derive_enum(
    ident: &Ident,
    attrs: &[syn::Attribute],
    data: &DataEnum,
) -> syn::Result<proc_macro2::TokenStream> {
    let container = parse_serde_attrs(attrs)?;
    if container.tag.is_none() {
        return Err(syn::Error::new(
            ident.span(),
            "StixProperties on enums requires container serde(tag = \"...\")",
        ));
    }

    let mut entries: Vec<proc_macro2::TokenStream> = Vec::new();
    for variant in &data.variants {
        let syn::Fields::Unnamed(unnamed) = &variant.fields else {
            return Err(syn::Error::new(
                variant.ident.span(),
                "StixProperties: enums must use newtype variants with exactly one inner type",
            ));
        };
        if unnamed.unnamed.len() != 1 {
            return Err(syn::Error::new(
                variant.ident.span(),
                "StixProperties: enums must use newtype variants with exactly one inner type",
            ));
        }
        let inner = strip_box(&unnamed.unnamed[0].ty)?;
        let variant_attrs = parse_serde_attrs(&variant.attrs)?;
        if variant_attrs.flatten {
            return Err(syn::Error::new(
                variant.ident.span(),
                "StixProperties: flattened enum variants are not supported",
            ));
        }
        let tag_name = match &variant_attrs.rename {
            Some(r) => r.clone(),
            None => match &container.rename_all {
                Some(style) => convert_case(&variant.ident.to_string(), style)?,
                None => variant.ident.to_string(),
            },
        };
        for name in std::iter::once(tag_name).chain(variant_attrs.alias) {
            let tag_lit = syn::LitStr::new(&name, proc_macro2::Span::call_site());
            entries.push(quote! {
                crate::properties::VariantProps {
                    tag: #tag_lit,
                    known: <#inner as crate::properties::StixProperties>::KNOWN,
                    required: <#inner as crate::properties::StixProperties>::REQUIRED,
                }
            });
        }
    }

    let const_ident = Ident::new(
        &(screaming_case(&ident.to_string()) + "_VARIANTS"),
        ident.span(),
    );
    Ok(quote! {
        pub const #const_ident: &'static [crate::properties::VariantProps] = &[#(#entries),*];
    })
}
