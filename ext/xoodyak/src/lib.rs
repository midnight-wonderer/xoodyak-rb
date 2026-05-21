use std::cell::RefCell;
use std::ffi::{c_int, c_uchar, c_void};
use std::mem::MaybeUninit;
use std::os::raw::c_char;
use magnus::{
    prelude::*, scan_args::scan_args, Error, ExceptionClass, RString, Ruby, Value,
};
use rb_sys::{VALUE, size_t};
use xoodyak::{XoodyakHash, XoodyakKeyed, XoodyakCommon, XoodyakError, XOODYAK_AUTH_TAG_BYTES};

// Low-level Digest bindings
pub const RUBY_DIGEST_API_VERSION: c_int = 3;

pub type RbDigestHashInitFuncT = unsafe extern "C" fn(*mut c_void) -> c_int;
pub type RbDigestHashUpdateFuncT = unsafe extern "C" fn(*mut c_void, *mut c_uchar, size_t);
pub type RbDigestHashFinishFuncT = unsafe extern "C" fn(*mut c_void, *mut c_uchar) -> c_int;

#[derive(Debug)]
#[repr(C)]
pub struct RbDigestMetadataT {
    pub api_version: c_int,
    pub digest_len: size_t,
    pub block_len: size_t,
    pub ctx_size: size_t,
    pub init_func: RbDigestHashInitFuncT,
    pub update_func: RbDigestHashUpdateFuncT,
    pub finish_func: RbDigestHashFinishFuncT,
}

#[allow(dead_code)]
type WrapperType = unsafe extern "C" fn(&'static RbDigestMetadataT) -> VALUE;

#[cfg(any(digest_use_rb_ext_resolve_symbol, ruby_gte_3_4))]
pub unsafe fn rb_digest_make_metadata(meta: &'static RbDigestMetadataT) -> VALUE {
    static mut WRAPPER: Option<WrapperType> = None;

    unsafe fn load_wrapper() {
        use rb_sys::rb_ext_resolve_symbol;
        use std::ffi::c_char;
        use std::sync::Once;

        static INIT: Once = Once::new();

        INIT.call_once(|| {
            let lib_name = "digest.so\0".as_ptr() as *const c_char;
            let symbol_name = "rb_digest_wrap_metadata\0".as_ptr() as *const c_char;
            let symbol_ptr = unsafe { rb_ext_resolve_symbol(lib_name, symbol_name) };

            if !symbol_ptr.is_null() {
                unsafe {
                    WRAPPER = Some(std::mem::transmute::<*mut c_void, WrapperType>(symbol_ptr));
                }
            } else {
                panic!("Failed to resolve rb_digest_wrap_metadata");
            }
        });
    }

    unsafe {
        load_wrapper();
        if let Some(wrapper) = WRAPPER {
            return wrapper(meta);
        }
    }
    panic!("Failed to resolve rb_digest_wrap_metadata");
}

#[cfg(not(any(digest_use_rb_ext_resolve_symbol, ruby_gte_3_4)))]
pub unsafe fn rb_digest_make_metadata(meta: &'static RbDigestMetadataT) -> VALUE {
    use rb_sys::{rb_data_object_wrap, rb_obj_freeze};
    unsafe {
        let data = rb_data_object_wrap(
            0 as VALUE,
            meta as *const RbDigestMetadataT as *mut c_void,
            None,
            None,
        );
        rb_obj_freeze(data)
    }
}

struct RbXoodyakDigestCtx {
    hash: XoodyakHash,
    buffer: [u8; 16],
    buf_len: usize,
    first_block_absorbed: bool,
}

// Struct to configure dynamic digest metadata
struct XoodyakDigest;

impl XoodyakDigest {
    const BLOCK_LEN: usize = 16;
    const DIGEST_LEN: usize = 32;

    fn digest_metadata() -> &'static RbDigestMetadataT {
        static DIGEST_METADATA: RbDigestMetadataT = RbDigestMetadataT {
            api_version: RUBY_DIGEST_API_VERSION,
            digest_len: XoodyakDigest::DIGEST_LEN as _,
            block_len: XoodyakDigest::BLOCK_LEN as _,
            ctx_size: std::mem::size_of::<RbXoodyakDigestCtx>() as _,
            init_func: XoodyakDigest::init_in_place,
            update_func: XoodyakDigest::update,
            finish_func: XoodyakDigest::finish,
        };
        &DIGEST_METADATA
    }

    extern "C" fn init_in_place(ctx: *mut c_void) -> c_int {
        let ctx = ctx as *mut MaybeUninit<RbXoodyakDigestCtx>;
        let ctx = unsafe { &mut *ctx };
        ctx.write(RbXoodyakDigestCtx {
            hash: XoodyakHash::new(),
            buffer: [0u8; 16],
            buf_len: 0,
            first_block_absorbed: false,
        });
        true as _
    }

    extern "C" fn update(ctx: *mut c_void, data: *mut c_uchar, len: size_t) {
        let ctx = ctx as *mut MaybeUninit<RbXoodyakDigestCtx>;
        let ctx = unsafe { &mut *ctx };
        let ctx = unsafe { ctx.assume_init_mut() };
        let mut slice = unsafe { std::slice::from_raw_parts(data, len as _) };

        while !slice.is_empty() {
            let space = 16 - ctx.buf_len;
            if slice.len() >= space {
                ctx.buffer[ctx.buf_len..16].copy_from_slice(&slice[..space]);
                slice = &slice[space..];

                if !ctx.first_block_absorbed {
                    ctx.hash.absorb(&ctx.buffer);
                    ctx.first_block_absorbed = true;
                } else {
                    ctx.hash.absorb_more(&ctx.buffer, 16);
                }
                ctx.buf_len = 0;
            } else {
                ctx.buffer[ctx.buf_len..ctx.buf_len + slice.len()].copy_from_slice(slice);
                ctx.buf_len += slice.len();
                break;
            }
        }
    }

    extern "C" fn finish(ctx: *mut c_void, digest: *mut c_uchar) -> c_int {
        let ctx = ctx as *mut MaybeUninit<RbXoodyakDigestCtx>;
        let ctx = unsafe { &mut *ctx };
        let ctx = unsafe { ctx.assume_init_mut() };

        if ctx.buf_len > 0 {
            if !ctx.first_block_absorbed {
                ctx.hash.absorb(&ctx.buffer[..ctx.buf_len]);
                ctx.first_block_absorbed = true;
            } else {
                ctx.hash.absorb_more(&ctx.buffer[..ctx.buf_len], 16);
            }
            ctx.buf_len = 0;
        }

        let outbuf = unsafe { std::slice::from_raw_parts_mut(digest, Self::DIGEST_LEN) };
        ctx.hash.squeeze(outbuf);
        true as _
    }
}

fn get_error_class(name: &str) -> Option<ExceptionClass> {
    let ruby = Ruby::get().unwrap();
    ruby.class_object()
        .const_get::<_, magnus::RClass>("Xoodyak")
        .ok()
        .and_then(|xoodyak| xoodyak.const_get::<_, ExceptionClass>(name).ok())
}

fn keyed_mode_error(msg: &'static str) -> Error {
    let ruby = Ruby::get().unwrap();
    if let Some(error_class) = get_error_class("KeyedModeError") {
        Error::new(error_class, msg)
    } else {
        Error::new(ruby.exception_runtime_error(), msg)
    }
}

// Custom error mapping
fn map_xoodyak_err(err: XoodyakError) -> Error {
    let ruby = Ruby::get().unwrap();
    match err {
        XoodyakError::InvalidBufferLength => {
            Error::new(ruby.exception_arg_error(), "invalid buffer length")
        }
        XoodyakError::InvalidParameterLength => {
            Error::new(ruby.exception_arg_error(), "invalid parameter length")
        }
        XoodyakError::KeyRequired => {
            Error::new(ruby.exception_arg_error(), "key required")
        }
        XoodyakError::TagMismatch => {
            if let Some(error_class) = get_error_class("VerificationError") {
                Error::new(error_class, "tag mismatch")
            } else {
                Error::new(ruby.exception_runtime_error(), "tag mismatch")
            }
        }
    }
}

// Unified Xoodyak class
#[derive(Clone)]
enum XoodyakState {
    Unkeyed(XoodyakHash),
    Keyed(XoodyakKeyed),
}

#[derive(magnus::TypedData, Clone)]
#[magnus(class = "Xoodyak", free_immediately)]
pub struct Xoodyak {
    state: RefCell<XoodyakState>,
}

impl Default for XoodyakState {
    fn default() -> Self {
        XoodyakState::Unkeyed(XoodyakHash::new())
    }
}

impl Default for Xoodyak {
    fn default() -> Self {
        Xoodyak {
            state: RefCell::new(XoodyakState::default()),
        }
    }
}

impl magnus::DataTypeFunctions for Xoodyak {}

impl Xoodyak {
    fn initialize(rb_self: magnus::typed_data::Obj<Self>, args: &[Value]) -> Result<(), Error> {
        let args = scan_args::<(), (Option<Option<RString>>, Option<Option<RString>>, Option<Option<RString>>, Option<Option<RString>>), (), (), (), ()>(args)?;
        let (key, nonce, key_id, counter) = args.optional;
        let key = key.flatten();
        let nonce = nonce.flatten();
        let key_id = key_id.flatten();
        let counter = counter.flatten();
        if let Some(k) = key {
            let key_bytes = unsafe { k.as_slice() };
            let nonce_bytes = nonce.as_ref().map(|n| unsafe { n.as_slice() });
            let key_id_bytes = key_id.as_ref().map(|ki| unsafe { ki.as_slice() });
            let counter_bytes = counter.as_ref().map(|c| unsafe { c.as_slice() });
            let keyed = XoodyakKeyed::new(key_bytes, nonce_bytes, key_id_bytes, counter_bytes)
                .map_err(map_xoodyak_err)?;
            *rb_self.state.borrow_mut() = XoodyakState::Keyed(keyed);
        } else {
            if nonce.is_some() || key_id.is_some() || counter.is_some() {
                return Err(Error::new(
                    Ruby::get().unwrap().exception_arg_error(),
                    "nonce, key_id, and counter can only be used in keyed mode (when key is provided)",
                ));
            }
            *rb_self.state.borrow_mut() = XoodyakState::Unkeyed(XoodyakHash::new());
        }
        Ok(())
    }

    fn initialize_copy(&self, other: &Xoodyak) -> Result<(), Error> {
        let other_state = other.state.borrow().clone();
        *self.state.borrow_mut() = other_state;
        Ok(())
    }

    fn absorb(&self, bin: RString) {
        let bin_bytes = unsafe { bin.as_slice() };
        match &mut *self.state.borrow_mut() {
            XoodyakState::Unkeyed(ref mut h) => h.absorb(bin_bytes),
            XoodyakState::Keyed(ref mut k) => k.absorb(bin_bytes),
        }
    }

    fn squeeze(&self, len: usize) -> RString {
        let mut buf = vec![0u8; len];
        match &mut *self.state.borrow_mut() {
            XoodyakState::Unkeyed(ref mut h) => h.squeeze(&mut buf),
            XoodyakState::Keyed(ref mut k) => k.squeeze(&mut buf),
        }
        Ruby::get().unwrap().str_from_slice(&buf)
    }

    fn squeeze_key(&self, len: usize) -> RString {
        let mut buf = vec![0u8; len];
        match &mut *self.state.borrow_mut() {
            XoodyakState::Unkeyed(ref mut h) => h.squeeze_key(&mut buf),
            XoodyakState::Keyed(ref mut k) => k.squeeze_key(&mut buf),
        }
        Ruby::get().unwrap().str_from_slice(&buf)
    }

    fn encrypt(&self, bin: RString) -> Result<RString, Error> {
        let bin_bytes = unsafe { bin.as_slice() };
        match &mut *self.state.borrow_mut() {
            XoodyakState::Unkeyed(_) => Err(keyed_mode_error("encrypt is only supported in keyed mode")),
            XoodyakState::Keyed(ref mut k) => {
                let mut out = vec![0u8; bin_bytes.len()];
                k.encrypt(&mut out, bin_bytes).map_err(map_xoodyak_err)?;
                Ok(Ruby::get().unwrap().str_from_slice(&out))
            }
        }
    }

    fn decrypt(&self, bin: RString) -> Result<RString, Error> {
        let bin_bytes = unsafe { bin.as_slice() };
        match &mut *self.state.borrow_mut() {
            XoodyakState::Unkeyed(_) => Err(keyed_mode_error("decrypt is only supported in keyed mode")),
            XoodyakState::Keyed(ref mut k) => {
                let mut out = vec![0u8; bin_bytes.len()];
                k.decrypt(&mut out, bin_bytes).map_err(map_xoodyak_err)?;
                Ok(Ruby::get().unwrap().str_from_slice(&out))
            }
        }
    }

    fn aead_encrypt(&self, bin: RString) -> Result<RString, Error> {
        let bin_bytes = unsafe { bin.as_slice() };
        match &mut *self.state.borrow_mut() {
            XoodyakState::Unkeyed(_) => Err(keyed_mode_error("aead_encrypt is only supported in keyed mode")),
            XoodyakState::Keyed(ref mut k) => {
                let mut out = vec![0u8; bin_bytes.len() + XOODYAK_AUTH_TAG_BYTES];
                k.aead_encrypt(&mut out, Some(bin_bytes)).map_err(map_xoodyak_err)?;
                Ok(Ruby::get().unwrap().str_from_slice(&out))
            }
        }
    }

    fn aead_decrypt(&self, bin: RString) -> Result<RString, Error> {
        let bin_bytes = unsafe { bin.as_slice() };
        match &mut *self.state.borrow_mut() {
            XoodyakState::Unkeyed(_) => Err(keyed_mode_error("aead_decrypt is only supported in keyed mode")),
            XoodyakState::Keyed(ref mut k) => {
                if bin_bytes.len() < XOODYAK_AUTH_TAG_BYTES {
                    return Err(Error::new(
                        Ruby::get().unwrap().exception_arg_error(),
                        "ciphertext is too short to contain a tag",
                    ));
                }
                let mut out = vec![0u8; bin_bytes.len() - XOODYAK_AUTH_TAG_BYTES];
                k.aead_decrypt(&mut out, bin_bytes).map_err(map_xoodyak_err)?;
                Ok(Ruby::get().unwrap().str_from_slice(&out))
            }
        }
    }

    fn aead_encrypt_detached(&self, bin: RString) -> Result<magnus::RArray, Error> {
        let bin_bytes = unsafe { bin.as_slice() };
        match &mut *self.state.borrow_mut() {
            XoodyakState::Unkeyed(_) => Err(keyed_mode_error("aead_encrypt_detached is only supported in keyed mode")),
            XoodyakState::Keyed(ref mut k) => {
                let mut out = vec![0u8; bin_bytes.len()];
                let tag = k.aead_encrypt_detached(&mut out, Some(bin_bytes)).map_err(map_xoodyak_err)?;
                let ruby = Ruby::get().unwrap();
                let ct_str = ruby.str_from_slice(&out);
                let tag_str = ruby.str_from_slice(tag.as_ref());
                Ok(ruby.ary_new_from_values(&[ct_str.as_value(), tag_str.as_value()]))
            }
        }
    }

    fn aead_decrypt_detached(&self, bin: RString, tag: RString) -> Result<RString, Error> {
        let bin_bytes = unsafe { bin.as_slice() };
        let tag_bytes = unsafe { tag.as_slice() };
        match &mut *self.state.borrow_mut() {
            XoodyakState::Unkeyed(_) => Err(keyed_mode_error("aead_decrypt_detached is only supported in keyed mode")),
            XoodyakState::Keyed(ref mut k) => {
                let t_array: [u8; XOODYAK_AUTH_TAG_BYTES] = tag_bytes.try_into().map_err(|_| {
                    Error::new(Ruby::get().unwrap().exception_arg_error(), "tag must be 16 bytes")
                })?;
                let mut out = vec![0u8; bin_bytes.len()];
                k.aead_decrypt_detached(&mut out, &t_array.into(), Some(bin_bytes))
                    .map_err(map_xoodyak_err)?;
                Ok(Ruby::get().unwrap().str_from_slice(&out))
            }
        }
    }

    fn ratchet(&self) -> Result<(), Error> {
        match &mut *self.state.borrow_mut() {
            XoodyakState::Unkeyed(_) => Err(keyed_mode_error("ratchet is only supported in keyed mode")),
            XoodyakState::Keyed(ref mut k) => {
                k.ratchet();
                Ok(())
            }
        }
    }
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    // Define the Xoodyak class at the top level
    let class = ruby.define_class("Xoodyak", ruby.class_object())?;
    class.define_alloc_func::<Xoodyak>();
    class.define_method("initialize", magnus::method!(Xoodyak::initialize, -1))?;
    class.define_method("initialize_copy", magnus::method!(Xoodyak::initialize_copy, 1))?;
    class.define_method("absorb", magnus::method!(Xoodyak::absorb, 1))?;
    class.define_method("squeeze", magnus::method!(Xoodyak::squeeze, 1))?;
    class.define_method("squeeze_key", magnus::method!(Xoodyak::squeeze_key, 1))?;
    class.define_method("encrypt", magnus::method!(Xoodyak::encrypt, 1))?;
    class.define_method("decrypt", magnus::method!(Xoodyak::decrypt, 1))?;
    class.define_method("aead_encrypt", magnus::method!(Xoodyak::aead_encrypt, 1))?;
    class.define_method("aead_decrypt", magnus::method!(Xoodyak::aead_decrypt, 1))?;
    class.define_method("aead_encrypt_detached", magnus::method!(Xoodyak::aead_encrypt_detached, 1))?;
    class.define_method("aead_decrypt_detached", magnus::method!(Xoodyak::aead_decrypt_detached, 2))?;
    class.define_method("ratchet", magnus::method!(Xoodyak::ratchet, 0))?;

    // Define the custom Error classes under Xoodyak class
    let error = class.define_error("Error", ruby.exception_standard_error())?;
    class.define_error("KeyedModeError", error)?;
    class.define_error("VerificationError", error)?;

    // Define Digest subclassing Digest::Base nested under Xoodyak class
    ruby.require("digest")?;
    let digest_module = ruby.define_module("Digest")?;
    let digest_base = digest_module.const_get::<_, magnus::RClass>("Base")?;
    let digest_klass = class.define_class("Digest", digest_base)?;

    use magnus::rb_sys::AsRawValue;
    let meta = unsafe { rb_digest_make_metadata(XoodyakDigest::digest_metadata()) };
    let metadata_id = unsafe { rb_sys::rb_intern("metadata\0".as_ptr() as *const c_char) };
    unsafe { rb_sys::rb_ivar_set(digest_klass.as_raw(), metadata_id, meta) };

    Ok(())
}
