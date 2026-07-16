use crate::data::{
    encode_raw_event_chunk, encode_raw_event_into, raw_event_size, transcode_raw_chunk, TraceBundleEvent,
    TraceBundleEventKind,
};
use crate::state::{
    helper_log, log_trace_stats, reset_trace_stats, update_max, TraceWriter, TRACE_CHUNK_SIZE, TRACE_MAX_CHUNK_BYTES,
    TRACE_MERGE_NS, TRACE_NEXT_SEQ, TRACE_PUBLISHED_SESSION, TRACE_PUBLISH_LOCK, TRACE_SESSION_SEQ, TRACE_TRANSCODE_NS,
    TRACE_WRITER,
};
use std::fs::{create_dir_all, remove_file, OpenOptions};
use std::io::{BufWriter, Write};
use std::sync::atomic::Ordering;

thread_local! {
    pub(crate) static TRACE_CHUNK_BUFFER: std::cell::RefCell<Vec<u8>> =
        std::cell::RefCell::new(Vec::with_capacity(TRACE_CHUNK_SIZE));
}

pub(crate) fn merged_bundle_tmp_path(base: &str, session_id: u64) -> String {
    format!("{}/trace_bundle.pb.s{}.tmp", base, session_id)
}

pub(crate) fn final_trace_path(base: &str) -> String {
    format!("{}/trace_bundle.pb", base)
}

fn open_trace_writer(base: &str, session_id: u64) -> Result<TraceWriter, String> {
    create_dir_all(base).map_err(|err| format!("create trace output dir {} failed: {}", base, err))?;
    let tmp_path = merged_bundle_tmp_path(base, session_id);
    let mut writer = BufWriter::new(
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|err| format!("open {} failed: {}", tmp_path, err))?,
    );
    writer
        .write_all(crate::state::TRACE_BUNDLE_MAGIC)
        .map_err(|err| format!("write trace header failed: {}", err))?;
    Ok(TraceWriter {
        session_id,
        writer,
        tmp_path,
        base: base.to_string(),
    })
}

pub(crate) fn start_trace_writer(base: &str) -> Result<(), String> {
    let mut guard = TRACE_WRITER.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_some() {
        return Err("trace session already active".to_string());
    }
    let session_id = TRACE_SESSION_SEQ.fetch_add(1, Ordering::Relaxed) + 1;
    TRACE_NEXT_SEQ.store(0, Ordering::Relaxed);
    reset_trace_stats();
    let writer = open_trace_writer(base, session_id)?;
    *guard = Some(writer);
    helper_log(&format!(
        "[qbdi-helper] trace writer started: base={} session={}",
        base, session_id
    ));
    Ok(())
}

fn submit_chunk(payload: Vec<u8>) {
    submit_chunk_inner(payload, false);
}

fn submit_dynamic_chunk(payload: Vec<u8>) {
    submit_chunk_inner(payload, true);
}

fn submit_chunk_inner(payload: Vec<u8>, dynamic: bool) {
    if payload.is_empty() {
        return;
    }
    let payload_len = payload.len();
    update_max(&TRACE_MAX_CHUNK_BYTES, payload_len as u64);
    let transcode_start = std::time::Instant::now();
    let encoded = match transcode_raw_chunk(&payload) {
        Ok(encoded) => encoded,
        Err(err) => {
            helper_log(&format!("[qbdi-helper] transcode raw chunk failed: {}", err));
            if dynamic {
                crate::state::TRACE_DYNAMIC_CHUNKS_DROPPED_DISCONNECTED.fetch_add(1, Ordering::Relaxed);
                crate::state::TRACE_DYNAMIC_BYTES_DROPPED_DISCONNECTED.fetch_add(payload_len as u64, Ordering::Relaxed);
            } else {
                crate::state::TRACE_CHUNKS_DROPPED_DISCONNECTED.fetch_add(1, Ordering::Relaxed);
                crate::state::TRACE_BYTES_DROPPED_DISCONNECTED.fetch_add(payload_len as u64, Ordering::Relaxed);
            }
            return;
        }
    };
    TRACE_TRANSCODE_NS.fetch_add(transcode_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
    let mut guard = TRACE_WRITER.lock().unwrap_or_else(|e| e.into_inner());
    let Some(writer) = guard.as_mut() else {
        helper_log("[qbdi-helper] trace writer missing");
        if dynamic {
            crate::state::TRACE_DYNAMIC_CHUNKS_DROPPED_DISCONNECTED.fetch_add(1, Ordering::Relaxed);
            crate::state::TRACE_DYNAMIC_BYTES_DROPPED_DISCONNECTED.fetch_add(payload_len as u64, Ordering::Relaxed);
        } else {
            crate::state::TRACE_CHUNKS_DROPPED_DISCONNECTED.fetch_add(1, Ordering::Relaxed);
            crate::state::TRACE_BYTES_DROPPED_DISCONNECTED.fetch_add(payload_len as u64, Ordering::Relaxed);
        }
        return;
    };
    if let Err(err) = writer.writer.write_all(&encoded) {
        helper_log(&format!("[qbdi-helper] write trace bundle failed: {}", err));
        if dynamic {
            crate::state::TRACE_DYNAMIC_CHUNKS_DROPPED_DISCONNECTED.fetch_add(1, Ordering::Relaxed);
            crate::state::TRACE_DYNAMIC_BYTES_DROPPED_DISCONNECTED.fetch_add(payload_len as u64, Ordering::Relaxed);
        } else {
            crate::state::TRACE_CHUNKS_DROPPED_DISCONNECTED.fetch_add(1, Ordering::Relaxed);
            crate::state::TRACE_BYTES_DROPPED_DISCONNECTED.fetch_add(payload_len as u64, Ordering::Relaxed);
        }
        return;
    }
    if dynamic {
        crate::state::TRACE_DYNAMIC_CHUNKS_SUBMITTED.fetch_add(1, Ordering::Relaxed);
    } else {
        crate::state::TRACE_CHUNKS_SUBMITTED.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn flush_thread_local_chunk() {
    TRACE_CHUNK_BUFFER.with(|buffer| {
        let mut buffer = buffer.borrow_mut();
        if !buffer.is_empty() {
            let payload = std::mem::take(&mut *buffer);
            buffer.reserve(TRACE_CHUNK_SIZE);
            submit_chunk(payload);
        }
    });
}

pub(crate) fn trace_send(event: TraceBundleEvent) {
    let raw_len = raw_event_size(&event);
    crate::state::TRACE_EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
    crate::state::TRACE_RAW_BYTES.fetch_add(raw_len as u64, Ordering::Relaxed);
    if raw_len > TRACE_CHUNK_SIZE {
        match event.kind.as_ref().expect("trace event kind exists") {
            TraceBundleEventKind::DynamicExecChunk(_) => submit_dynamic_chunk(encode_raw_event_chunk(&event)),
            _ => submit_chunk(encode_raw_event_chunk(&event)),
        }
        return;
    }

    TRACE_CHUNK_BUFFER.with(|buffer| {
        let mut buffer = buffer.borrow_mut();
        if buffer.len() + raw_len > TRACE_CHUNK_SIZE {
            let payload = std::mem::take(&mut *buffer);
            buffer.reserve(TRACE_CHUNK_SIZE);
            submit_chunk(payload);
        }
        match event.kind.as_ref().expect("trace event kind exists") {
            TraceBundleEventKind::DynamicExecChunk(_) => submit_dynamic_chunk(encode_raw_event_chunk(&event)),
            _ => encode_raw_event_into(&mut *buffer, &event),
        }
    });
}

fn publish_bundle(base: &str, session_id: u64, tmp_path: &str) -> Result<(), String> {
    let final_path = final_trace_path(base);
    let _guard = TRACE_PUBLISH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let published = TRACE_PUBLISHED_SESSION.load(Ordering::Relaxed);
    if session_id < published {
        let _ = remove_file(tmp_path);
        return Ok(());
    }
    std::fs::rename(tmp_path, &final_path).map_err(|err| format!("publish {} failed: {}", final_path, err))?;
    TRACE_PUBLISHED_SESSION.store(session_id, Ordering::Relaxed);
    Ok(())
}

fn finalize_trace_writer(mut writer: TraceWriter) {
    let merge_start = std::time::Instant::now();
    helper_log(&format!(
        "[qbdi-helper] finalize trace writer start: base={} session={}",
        writer.base, writer.session_id
    ));
    if let Err(err) = writer.writer.flush() {
        helper_log(&format!("[qbdi-helper] flush trace bundle failed: {}", err));
    }
    drop(writer.writer);
    if let Err(err) = publish_bundle(&writer.base, writer.session_id, &writer.tmp_path) {
        helper_log(&format!("[qbdi-helper] publish trace bundle failed: {}", err));
    }
    TRACE_MERGE_NS.fetch_add(merge_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
    helper_log("[qbdi-helper] finalize trace writer done");
    log_trace_stats(&writer.base);
}

pub(crate) fn finalize_trace_session_async() {
    flush_thread_local_chunk();
    let writer = {
        let mut guard = TRACE_WRITER.lock().unwrap_or_else(|e| e.into_inner());
        guard.take()
    };
    if let Some(writer) = writer {
        finalize_trace_writer(writer);
    }
}

pub(crate) fn shutdown_trace_writer() {
    finalize_trace_session_async();
}
