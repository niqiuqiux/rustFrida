//! `send()` / `recv()` — the standard Frida message channel.
//!
//! `send()` hands a JSON string plus optional binary data to the transport the
//! agent installed; rustFrida carries it over its own socket rather than
//! Frida's session protocol, but the script-facing shape is the same.
//!
//! `recv()` registers a one-shot callback. Messages that arrive with no
//! matching callback are queued, so a script that posts before the agent is
//! ready does not lose them.

use crate::ffi;
use crate::jsapi::callback_util::{acquire_js_engine_for_callback, handle_js_exception, throw_internal_error};
use crate::value::JSValue;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Installed by the agent: delivers one message to the host.
pub type MessageSink = fn(&str, Option<&[u8]>) -> Result<(), String>;

static MESSAGE_SINK: Mutex<Option<MessageSink>> = Mutex::new(None);

/// Messages received from the host that no callback has claimed yet.
struct PendingMessage {
    json: String,
    data: Option<Vec<u8>>,
}

static INBOX: Mutex<VecDeque<PendingMessage>> = Mutex::new(VecDeque::new());
/// Context that owns the script-facing globals, set when they are registered.
static MESSAGE_CONTEXT: AtomicUsize = AtomicUsize::new(0);

pub fn install_message_sink(sink: MessageSink) {
    *MESSAGE_SINK.lock().unwrap_or_else(|error| error.into_inner()) = Some(sink);
}

/// Drop the transport, the queue and the context reference.
///
/// Called from the cleanup path so a message arriving mid-teardown cannot be
/// delivered into a runtime that is going away.
pub fn clear_message_sink() {
    *MESSAGE_SINK.lock().unwrap_or_else(|error| error.into_inner()) = None;
    MESSAGE_CONTEXT.store(0, Ordering::SeqCst);
    INBOX.lock().unwrap_or_else(|error| error.into_inner()).clear();
}

/// Queue a message from the host and try to hand it to a waiting callback.
///
/// Called from the agent's socket thread, so it enters JavaScript through the
/// engine guard like every other native callback.
pub fn post_message(json: String, data: Option<Vec<u8>>) {
    let context = MESSAGE_CONTEXT.load(Ordering::SeqCst);
    if context == 0 {
        return;
    }
    INBOX
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .push_back(PendingMessage { json, data });

    let ctx = context as *mut ffi::JSContext;
    unsafe {
        let Some(_guard) = acquire_js_engine_for_callback(ctx, "recv delivery", 0) else {
            // The runtime is busy; the message stays queued until the script
            // registers a callback or drains it itself.
            return;
        };
        deliver_pending(ctx);
    }
}

/// Hand queued messages to `__rf_dispatch_message` until it stops accepting.
unsafe fn deliver_pending(ctx: *mut ffi::JSContext) {
    loop {
        let next = INBOX.lock().unwrap_or_else(|error| error.into_inner()).pop_front();
        let Some(message) = next else {
            return;
        };

        let global = ffi::JS_GetGlobalObject(ctx);
        let dispatch = JSValue(ffi::JS_GetPropertyStr(ctx, global, c"__rf_dispatch_message".as_ptr()));
        if !dispatch.is_function(ctx) {
            dispatch.free(ctx);
            ffi::qjs_free_value(ctx, global);
            // Put it back: the script may register a callback later.
            INBOX
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push_front(message);
            return;
        }

        let json = ffi::JS_NewStringLen(ctx, message.json.as_ptr() as *const _, message.json.len());
        let data = match &message.data {
            Some(bytes) => ffi::JS_NewArrayBufferCopy(ctx, bytes.as_ptr(), bytes.len()),
            None => JSValue::null().raw(),
        };
        let arguments = [json, data];
        let result = ffi::JS_Call(
            ctx,
            dispatch.raw(),
            global,
            arguments.len() as i32,
            arguments.as_ptr() as *mut _,
        );
        let accepted = !handle_js_exception(ctx, result, "recv") && JSValue(result).to_bool().unwrap_or(false);
        ffi::qjs_free_value(ctx, result);
        for argument in arguments {
            ffi::qjs_free_value(ctx, argument);
        }
        dispatch.free(ctx);
        ffi::qjs_free_value(ctx, global);
        crate::jsapi::timers::drain_pending_jobs(ctx);

        if !accepted {
            // No callback wanted it; leave it queued for a later recv().
            INBOX
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push_front(message);
            return;
        }
    }
}

unsafe extern "C" fn js_send(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return throw_internal_error(ctx, "send() requires a message");
    }
    let Some(json) = JSValue(*argv).to_string(ctx) else {
        return throw_internal_error(ctx, "send() message must be a string");
    };

    let mut payload: Option<Vec<u8>> = None;
    if argc >= 2 {
        let data = JSValue(*argv.add(1));
        if !data.is_undefined() && !data.is_null() {
            match crate::jsapi::memory::extract_bytes(ctx, data) {
                Ok(bytes) => payload = Some(bytes),
                Err(error) => return error,
            }
        }
    }

    let sink = *MESSAGE_SINK.lock().unwrap_or_else(|error| error.into_inner());
    let Some(sink) = sink else {
        return throw_internal_error(ctx, "send() has no transport; the agent did not install one");
    };
    if let Err(error) = sink(&json, payload.as_deref()) {
        return throw_internal_error(ctx, format!("send(): {error}"));
    }
    JSValue::undefined().raw()
}

/// `__rf_drain_messages()` — let a script pull queued messages after
/// registering a callback, without waiting for the next post.
unsafe extern "C" fn js_drain_messages(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    deliver_pending(ctx);
    JSValue::undefined().raw()
}

unsafe extern "C" fn js_pending_message_count(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let count = INBOX.lock().unwrap_or_else(|error| error.into_inner()).len();
    ffi::qjs_new_int64(ctx, count as i64)
}

pub fn register_messaging_api(ctx: &crate::context::JSContext) {
    use crate::jsapi::util::add_cfunction_to_object;

    MESSAGE_CONTEXT.store(ctx.as_ptr() as usize, Ordering::SeqCst);
    let global = ctx.global_object();
    unsafe {
        let raw = global.raw();
        add_cfunction_to_object(ctx.as_ptr(), raw, "__rf_send", js_send, 2);
        add_cfunction_to_object(ctx.as_ptr(), raw, "__rf_drain_messages", js_drain_messages, 0);
        add_cfunction_to_object(
            ctx.as_ptr(),
            raw,
            "__rf_pending_message_count",
            js_pending_message_count,
            0,
        );
    }
    global.free(ctx.as_ptr());
}
