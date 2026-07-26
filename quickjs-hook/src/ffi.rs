//! FFI bindings for QuickJS and hook_engine

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(clippy::all)]
// bindgen 为位域访问器生成的 transmute，本文件全是机器生成的代码，无从修改。
#![allow(unnecessary_transmutes)]

// Include the generated QuickJS bindings
include!(concat!(env!("OUT_DIR"), "/quickjs_bindings.rs"));

// Include the generated hook_engine bindings
pub mod hook {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]

    include!(concat!(env!("OUT_DIR"), "/hook_bindings.rs"));
}
