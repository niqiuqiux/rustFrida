//! Frida-compatible signed and unsigned 64-bit integer wrappers.

use crate::context::JSContext;

pub fn register_int64_api(ctx: &JSContext) {
    match ctx.eval(include_str!("int64_boot.js"), "<int64_boot>") {
        Ok(value) => value.free(ctx.as_ptr()),
        Err(error) => crate::jsapi::console::output_message(&format!("[int64] bootstrap failed: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use crate::JSEngine;

    #[test]
    fn wraps_and_operates_at_64_bits() {
        let engine = JSEngine::new().expect("engine");
        let result = engine
            .eval(
                r#"
                (() => {
                    const signed = new Int64("0x7fffffffffffffff").add(1);
                    const unsigned = new UInt64("0xffffffffffffffff").add(1);
                    return signed.toString() === "-9223372036854775808" &&
                        signed.toString(16) === "-8000000000000000" &&
                        unsigned.toString() === "0" &&
                        new UInt64("-1").toString(16) === "ffffffffffffffff" &&
                        new Int64(-1).shr(1).toString() === "-1" &&
                        JSON.stringify(new UInt64("18446744073709551615")) ===
                            '"18446744073709551615"';
                })()
                "#,
            )
            .expect("eval");
        assert_eq!(result.to_bool(), Some(true));
        result.free(engine.context().as_ptr());
    }
}
