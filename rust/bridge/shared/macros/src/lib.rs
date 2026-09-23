//! Proc macros for the autocipher bridge.
//!
//! ## `#[ac_fn(...)]`
//!
//! Applied to a plain `pub fn` in `autocipher-bridge`. It expands into:
//!
//! 1. the original function unchanged (the "definition"),
//! 2. an `extern "C"` **export** `autocipher_{id}(...) -> int32` that marshals
//!    the definition's arguments and result across the boundary, maps engine
//!    errors to [`ErrorCode`][ErrCode] numbers via
//!    [`autocipher_bridge_types::map_error`], contains panics, and records the
//!    diagnostic message,
//! 3. a [`FnSpec`][FnSpecMeta] entry pushed into
//!    [`AC_FN_ITEMS`][Slice] (a `linkme` distributed slice) that the codegen
//!    runners enumerate to emit the C header and the per-language bindings.
//!
//! The C ABI is the single canonical boundary (Dart, Swift, and — later —
//! JNI/Node all consume it), so the language-specific codegen is driven purely
//! by the metadata; no per-language Rust features are involved for now.
//!
//! Supported parameter types (matched by spelling):
//! - the first parameter may be `&Vault` / `&mut Vault` — the opaque handle;
//! - `&str` — a borrowed UTF-8 string (passed as `*const u8` + `usize`);
//! - `&[u8]` — borrowed raw bytes (passed as `*const u8` + `usize`);
//! - `u64`, `u32` — integers passed by value.
//!
//! Supported return types:
//! `Result<(), FormatError>`, `Result<u32, FormatError>`,
//! `Result<u64, FormatError>`, `Result<Vec<u8>, FormatError>`,
//! `Result<Vault, FormatError>` (returns an owned handle).
//!
//! Attribute arguments:
//! - `nice = "addPaths"` — user-facing name in generated bindings;
//! - `opening` — mark the op as opening a vault (AEAD failures map to
//!   `WRONG_PASSWORD`);
//! - `doc = "…"` — documentation bubble for the generated binding.
//!
//! [ErrCode]: https://docs.rs/autocipher-proto
//! [FnSpecMeta]: autocipher_bridge_types__::FnSpec
//! [Slice]: autocipher_bridge_types__::AC_FN_ITEMS
//! [`autocipher_bridge_types::map_error`]: autocipher_bridge_types__::map_error

use proc_macro::TokenStream;
use proc_macro2::TokenStream as Tokens;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::parse_macro_input;
use syn::{FnArg, ItemFn, Meta, Result as SynResult, ReturnType, Type};

/// Attribute arguments: `nice`, `opening`, `doc`.
#[derive(Default)]
struct AcFnAttrs {
    nice: Option<String>,
    opening: bool,
    doc: String,
}

impl Parse for AcFnAttrs {
    fn parse(input: ParseStream) -> SynResult<Self> {
        let metas =
            input.call(syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated)?;
        let mut out = AcFnAttrs::default();
        for meta in metas {
            match meta {
                Meta::NameValue(nv) => {
                    if nv.path.is_ident("nice") {
                        if let syn::Expr::Lit(syn::ExprLit {
                            lit: syn::Lit::Str(s),
                            ..
                        }) = nv.value
                        {
                            out.nice = Some(s.value());
                        } else {
                            return Err(syn::Error::new_spanned(
                                nv,
                                "`nice` must be a string literal",
                            ));
                        }
                    } else if nv.path.is_ident("doc") {
                        if let syn::Expr::Lit(syn::ExprLit {
                            lit: syn::Lit::Str(s),
                            ..
                        }) = nv.value
                        {
                            out.doc = s.value();
                        } else {
                            return Err(syn::Error::new_spanned(
                                nv,
                                "`doc` must be a string literal",
                            ));
                        }
                    } else {
                        return Err(syn::Error::new_spanned(nv.path, "unknown `ac_fn` argument"));
                    }
                }
                Meta::Path(p) if p.is_ident("opening") => out.opening = true,
                other => {
                    return Err(syn::Error::new_spanned(
                        other,
                        "expected `nice = \"..\"`, `opening`, or `doc = \"..\"`",
                    ));
                }
            }
        }
        Ok(out)
    }
}

/// The ABI return kind of an ac_fn definition.
#[derive(Clone, Copy, PartialEq)]
enum Ret {
    Unit,
    U32,
    U64,
    Buffer,
    Handle,
}

impl Ret {
    /// The metadata tag used by the codegen runners.
    fn tag(self) -> &'static str {
        match self {
            Ret::Unit => "Unit",
            Ret::U32 => "U32",
            Ret::U64 => "U64",
            Ret::Buffer => "Buffer",
            Ret::Handle => "Handle",
        }
    }
}

/// The ABI parameter kind of an ac_fn argument.
#[derive(Clone, Copy, PartialEq)]
enum ArgKind {
    Handle,
    String,
    BytesIn,
    U64,
    U32,
}

impl ArgKind {
    fn tag(self) -> &'static str {
        match self {
            ArgKind::Handle => "Handle",
            ArgKind::String => "String",
            ArgKind::BytesIn => "BytesIn",
            ArgKind::U64 => "U64",
            ArgKind::U32 => "U32",
        }
    }
}

/// Last path segment of a type, if it is a plain path/`Self`-free identifier.
fn last_seg(ty: &Type) -> Option<&syn::PathSegment> {
    let Type::Path(p) = ty else { return None };
    p.path.segments.last()
}

fn classify(ty: &Type, is_first: bool, is_handle: bool) -> SynResult<(ArgKind, bool)> {
    match ty {
        Type::Reference(r) => {
            let elem = &*r.elem;
            if is_first && last_seg(elem).is_some_and(|s| s.ident == "Vault") {
                return Ok((ArgKind::Handle, true));
            }
            if last_seg(elem).is_some_and(|s| s.ident == "Vault") {
                return Err(syn::Error::new_spanned(
                    ty,
                    "the `Vault` handle must be the first parameter",
                ));
            }
            if last_seg(elem).is_some_and(|s| s.ident == "str") {
                return Ok((ArgKind::String, is_handle));
            }
            let Type::Slice(sl) = elem else {
                return Err(syn::Error::new_spanned(
                    ty,
                    "unsupported ac_fn parameter type",
                ));
            };
            if last_seg(&sl.elem).is_some_and(|s| s.ident == "u8") {
                Ok((ArgKind::BytesIn, is_handle))
            } else {
                Err(syn::Error::new_spanned(
                    ty,
                    "only `&[u8]` slices are supported",
                ))
            }
        }
        Type::Path(_) => {
            let seg = last_seg(ty).expect("checked above");
            match seg.ident.to_string().as_str() {
                "u64" => Ok((ArgKind::U64, is_handle)),
                "u32" => Ok((ArgKind::U32, is_handle)),
                _ => Err(syn::Error::new_spanned(
                    ty,
                    "unsupported ac_fn parameter type",
                )),
            }
        }
        _ => Err(syn::Error::new_spanned(
            ty,
            "unsupported ac_fn parameter type",
        )),
    }
}

fn parse_return(rt: &ReturnType) -> SynResult<(Ret, bool /* is_handle via Vault */)> {
    let ReturnType::Type(_, ty) = rt else {
        return Err(syn::Error::new_spanned(
            rt,
            "ac_fn requires a `Result<.., FormatError>` return",
        ));
    };
    let path = {
        let Type::Path(p) = &**ty else {
            return Err(syn::Error::new_spanned(
                ty,
                "ac_fn requires a `Result<.., FormatError>` return",
            ));
        };
        p
    };
    let seg = path.path.segments.last().ok_or_else(|| {
        syn::Error::new_spanned(ty, "ac_fn requires a `Result<.., FormatError>` return")
    })?;
    if seg.ident != "Result" {
        return Err(syn::Error::new_spanned(
            ty,
            "ac_fn requires a `Result<.., FormatError>` return",
        ));
    }
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return Err(syn::Error::new_spanned(seg, "malformed `Result` type"));
    };
    let mut it = args.args.iter();
    let ok_ty = it
        .next()
        .and_then(|a| match a {
            syn::GenericArgument::Type(t) => Some(t),
            _ => None,
        })
        .ok_or_else(|| syn::Error::new_spanned(seg, "malformed `Result` type"))?;
    let err_ty = it
        .next()
        .and_then(|a| match a {
            syn::GenericArgument::Type(t) => Some(t),
            _ => None,
        })
        .ok_or_else(|| syn::Error::new_spanned(seg, "malformed `Result` type"))?;
    if !last_seg(err_ty).is_some_and(|s| s.ident == "FormatError") {
        return Err(syn::Error::new_spanned(
            err_ty,
            "ac_fn error type must be `autocipher_format::FormatError`",
        ));
    }
    if matches!(last_seg(ok_ty), Some(s) if s.ident == "Vault") {
        return Ok((Ret::Handle, false));
    }
    match ok_ty {
        Type::Tuple(t) if t.elems.is_empty() => Ok((Ret::Unit, false)),
        _ => {
            let seg = last_seg(ok_ty)
                .ok_or_else(|| syn::Error::new_spanned(&ok_ty, "unsupported ac_fn return type"))?;
            match seg.ident.to_string().as_str() {
                "u32" => Ok((Ret::U32, false)),
                "u64" => Ok((Ret::U64, false)),
                "Vec" => {
                    // Require Vec<u8>.
                    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
                        return Err(syn::Error::new_spanned(
                            seg,
                            "unsupported ac_fn return type",
                        ));
                    };
                    let inner = args
                        .args
                        .iter()
                        .find_map(|a| match a {
                            syn::GenericArgument::Type(t) => Some(t),
                            _ => None,
                        })
                        .ok_or_else(|| syn::Error::new_spanned(seg, "malformed `Vec` type"))?;
                    if last_seg(inner).is_some_and(|s| s.ident == "u8") {
                        Ok((Ret::Buffer, false))
                    } else {
                        Err(syn::Error::new_spanned(
                            seg,
                            "only `Vec<u8>` buffers are supported",
                        ))
                    }
                }
                _ => Err(syn::Error::new_spanned(
                    &ok_ty,
                    "unsupported ac_fn return type",
                )),
            }
        }
    }
}

/// Expand `#[ac_fn(..)] pub fn ..(..) -> Result<.., FormatError>`.
#[proc_macro_attribute]
pub fn ac_fn(args: TokenStream, input: TokenStream) -> TokenStream {
    let attrs = parse_macro_input!(args as AcFnAttrs);
    let func = parse_macro_input!(input as ItemFn);
    match expand_ac_fn(&attrs, &func) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_ac_fn(attrs: &AcFnAttrs, func: &ItemFn) -> SynResult<Tokens> {
    let id = &func.sig.ident;
    let id_str = id.to_string();
    let symbol_str = format!("autocipher_{id_str}");
    let symbol = format_ident!("{}", symbol_str);
    let nice_str = attrs
        .nice
        .clone()
        .unwrap_or_else(|| id_str.strip_prefix("vault_").unwrap_or(&id_str).to_string());

    // Classify every parameter.
    let mut arg_infos = Vec::new();
    let mut call_args = Vec::new();
    let mut is_handle = false;
    let mut saw_handle = false;
    for (idx, arg) in func.sig.inputs.iter().enumerate() {
        let FnArg::Typed(pat) = arg else {
            return Err(syn::Error::new_spanned(arg, "ac_fn cannot take a receiver"));
        };
        let syn::Pat::Ident(name) = &*pat.pat else {
            return Err(syn::Error::new_spanned(
                pat,
                "ac_fn parameters must be plain identifiers",
            ));
        };
        let (kind, now_handle) = classify(&pat.ty, idx == 0, saw_handle)?;
        is_handle |= now_handle;
        saw_handle |= now_handle;
        arg_infos.push((name.ident.clone(), kind));
        call_args.push(name.ident.clone());
    }

    let (ret, _) = parse_return(&func.sig.output)?;

    // Emit: original definition (unchanged) …
    let mut out = Tokens::new();
    {
        let mut defn = func.clone();
        defn.attrs.retain(|_| true);
        out.extend(quote!(#defn));
    }

    // … the FnSpec metadata item …
    let spec_ident = format_ident!("__ACFN_{}", id_str);
    let arg_specs = arg_infos
        .iter()
        .filter(|(_, kind)| *kind != ArgKind::Handle)
        .map(|(name, kind)| {
            let n = name.to_string();
            let t = kind.tag();
            quote!(autocipher_bridge_types::ArgSpec::new(#n, #t))
        });
    let ret_tag = ret.tag();
    let ret_lit = ret_tag;
    let doc_lit = &attrs.doc;
    let nice_lit = &nice_str;
    let symbol_lit = &symbol_str;
    let is_handle_lit = is_handle;
    out.extend(quote! {
        #[linkme::distributed_slice(autocipher_bridge_types::AC_FN_ITEMS)]
        #[doc(hidden)]
        pub static #spec_ident: autocipher_bridge_types::FnSpec = autocipher_bridge_types::FnSpec {
            id: #id_str,
            symbol: #symbol_lit,
            nice: #nice_lit,
            is_handle: #is_handle_lit,
            args: &[#(#arg_specs,)*],
            ret: #ret_lit,
            doc: #doc_lit,
        };
    });

    // … and the C export.
    let mut c_params = Vec::new();
    let mut convs = Vec::new();
    for (name, kind) in &arg_infos {
        let name_len = format_ident!("{}_len", name);
        match kind {
            ArgKind::Handle => {
                c_params.push(quote!(#name: *const std::ffi::c_void));
                convs.push(quote! {
                    let #name = &mut *(#name as *mut autocipher_format::Vault);
                });
            }
            ArgKind::String => {
                c_params.push(quote!(#name: *const u8));
                c_params.push(quote!(#name_len: usize));
                convs.push(quote! {
                    let #name = if #name.is_null() {
                        ""
                    } else {
                        let __bytes = std::slice::from_raw_parts(#name, #name_len);
                        match std::str::from_utf8(__bytes) {
                            Ok(__s) => __s,
                            Err(_) => return Err(autocipher_bridge_types::AcErr::Code(
                                autocipher_bridge_types::ERR_INVALID_ARGUMENT,
                            )),
                        }
                    };
                });
            }
            ArgKind::BytesIn => {
                c_params.push(quote!(#name: *const u8));
                c_params.push(quote!(#name_len: usize));
                convs.push(quote! {
                    let #name = std::slice::from_raw_parts(#name, #name_len);
                });
            }
            ArgKind::U64 => c_params.push(quote!(#name: u64)),
            ArgKind::U32 => c_params.push(quote!(#name: u32)),
        }
    }

    // Output parameters appended after the input parameters.
    let (out_params, write_out) = match ret {
        Ret::Unit => (Tokens::new(), quote!(let _ = __ok;)),
        Ret::U32 => (
            quote!(count: *mut u32),
            quote! {
                unsafe { *count = __ok; }
            },
        ),
        Ret::U64 => (
            quote!(out: *mut u64),
            quote! {
                unsafe { *out = __ok; }
            },
        ),
        Ret::Buffer => (
            quote!(out: *mut autocipher_bridge_types::AcOutBuffer),
            quote! {
                let __data: Vec<u8> = __ok;
                let __need = __data.len();
                let __ob = unsafe { &mut *out };
                if !__ob.base.is_null() && __ob.len >= __need {
                    unsafe {
                        if __need != 0 {
                            std::ptr::copy_nonoverlapping(__data.as_ptr(), __ob.base, __need);
                        }
                    }
                    __ob.len = __need;
                } else {
                    __ob.base = std::ptr::null_mut();
                    __ob.len = __need;
                }
            },
        ),
        Ret::Handle => (
            quote!(out_handle: *mut *mut std::ffi::c_void),
            quote! {
                let __boxed = Box::into_raw(Box::new(__ok));
                unsafe { *out_handle = __boxed as *mut std::ffi::c_void; }
            },
        ),
    };

    let call = {
        let c = &call_args[..];
        quote!(#id(#(#c),*))
    };
    let opening_lit = attrs.opening;
    let wrapper_name = &symbol;
    let body = quote! {{
        let __r: Result<Result<_, autocipher_bridge_types::AcErr>, Box<dyn std::any::Any + Send>> =
            ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| -> Result<_, autocipher_bridge_types::AcErr> {
                #(#convs)*
                #call.map_err(autocipher_bridge_types::AcErr::Engine)
            }));
        match __r {
            Ok(Ok(__ok)) => {
                #write_out
                0
            }
            Ok(Err(autocipher_bridge_types::AcErr::Code(__code))) => {
                autocipher_bridge_types::set_last_error(
                    "request rejected at the ABI edge".into(),
                );
                __code
            }
            Ok(Err(autocipher_bridge_types::AcErr::Engine(__e))) => {
                autocipher_bridge_types::set_last_error(__e.to_string());
                autocipher_bridge_types::map_error(&__e, #opening_lit)
            }
            Err(_) => {
                autocipher_bridge_types::set_last_error(
                    "panicked at the autocipher ABI edge".into(),
                );
                autocipher_bridge_types::ERR_INTERNAL
            }
        }
    }};

    out.extend(quote! {
        #[allow(non_snake_case, clippy::missing_safety_doc, clippy::redundant_closure)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn #wrapper_name(
            #(#c_params,)*
            #out_params
        ) -> i32 {
            unsafe #body
        }
    });
    Ok(out)
}
