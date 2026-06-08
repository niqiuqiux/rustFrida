use std::env;
use std::fmt::Write as _;
use std::fs;

const TRACE_BUNDLE_MAGIC: &[u8; 4] = b"TRB1";

#[derive(Default)]
struct Options {
    input: String,
    limit: Option<usize>,
    summary_only: bool,
}

#[derive(Default)]
struct TraceState {
    module_path: Option<String>,
    module_base: u64,
}

#[derive(Default)]
struct Stats {
    total: usize,
    instructions: usize,
    mem_accesses: usize,
    external_returns: usize,
    dynamic_chunks: usize,
    contexts: usize,
    metadata: usize,
    unknown: usize,
}

#[derive(Debug)]
enum Event {
    InstructionAddr(u64),
    MemAccess(MemAccess),
    ExternalReturn(ExternalReturn),
    DynamicExecChunk(DynamicExecChunk),
    TraceContext(TraceContext),
    TraceBundleMetadata(TraceBundleMetadata),
    Unknown,
}

#[derive(Debug, Default)]
struct MemAccess {
    inst_addr: u64,
    access_addr: u64,
    value: u64,
    size: u32,
}

#[derive(Debug, Default)]
struct ExternalReturn {
    return_addr: u64,
    return_value: u64,
}

#[derive(Debug, Default)]
struct DynamicExecChunk {
    start_addr: u64,
    end_addr: u64,
    perm: u32,
    path: String,
    chunk_offset: u64,
    data_len: usize,
}

#[derive(Debug, Default)]
struct TraceContext {
    x: Vec<u64>,
    sp: u64,
    pc: u64,
    nzcv: u64,
    tpidr_el0: u64,
    q_words: usize,
    fpcr: u64,
    fpsr: u64,
}

#[derive(Debug, Default)]
struct TraceBundleMetadata {
    module_path: String,
    module_base: u64,
}

fn usage(program: &str) -> String {
    format!("usage: {program} [--limit N] [--summary-only] <trace_bundle.pb>")
}

fn parse_args() -> Result<Options, String> {
    let mut args = env::args().collect::<Vec<_>>();
    let program = args.first().cloned().unwrap_or_else(|| "qbdi-trace-dump".to_string());
    args.remove(0);

    let mut options = Options::default();
    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--help" | "-h" => return Err(usage(&program)),
            "--summary-only" => {
                options.summary_only = true;
                idx += 1;
            }
            "--limit" => {
                let value = args
                    .get(idx + 1)
                    .ok_or_else(|| format!("--limit requires a value\n{}", usage(&program)))?;
                options.limit = Some(
                    value
                        .parse::<usize>()
                        .map_err(|err| format!("invalid --limit value {value}: {err}"))?,
                );
                idx += 2;
            }
            value if value.starts_with('-') => return Err(format!("unknown option {value}\n{}", usage(&program))),
            value => {
                if !options.input.is_empty() {
                    return Err(format!("multiple input files provided\n{}", usage(&program)));
                }
                options.input = value.to_string();
                idx += 1;
            }
        }
    }

    if options.input.is_empty() {
        return Err(usage(&program));
    }
    Ok(options)
}

fn read_varint(cursor: &mut usize, data: &[u8]) -> Result<u64, String> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *data.get(*cursor).ok_or_else(|| "truncated varint".to_string())?;
        *cursor += 1;
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err("varint is too long".to_string())
}

fn read_len<'a>(cursor: &mut usize, data: &'a [u8]) -> Result<&'a [u8], String> {
    let len = read_varint(cursor, data)? as usize;
    let end = cursor.checked_add(len).ok_or_else(|| "length overflow".to_string())?;
    let bytes = data
        .get(*cursor..end)
        .ok_or_else(|| "truncated length-delimited field".to_string())?;
    *cursor = end;
    Ok(bytes)
}

fn read_string(cursor: &mut usize, data: &[u8]) -> Result<String, String> {
    String::from_utf8(read_len(cursor, data)?.to_vec()).map_err(|err| format!("invalid utf-8 string: {err}"))
}

fn skip_field(wire_type: u64, cursor: &mut usize, data: &[u8]) -> Result<(), String> {
    match wire_type {
        0 => {
            let _ = read_varint(cursor, data)?;
            Ok(())
        }
        1 => {
            *cursor = cursor
                .checked_add(8)
                .ok_or_else(|| "fixed64 skip overflow".to_string())?;
            if *cursor <= data.len() {
                Ok(())
            } else {
                Err("truncated fixed64 field".to_string())
            }
        }
        2 => {
            let _ = read_len(cursor, data)?;
            Ok(())
        }
        5 => {
            *cursor = cursor
                .checked_add(4)
                .ok_or_else(|| "fixed32 skip overflow".to_string())?;
            if *cursor <= data.len() {
                Ok(())
            } else {
                Err("truncated fixed32 field".to_string())
            }
        }
        other => Err(format!("unsupported protobuf wire type {other}")),
    }
}

fn read_repeated_u64(wire_type: u64, cursor: &mut usize, data: &[u8]) -> Result<Vec<u64>, String> {
    match wire_type {
        0 => Ok(vec![read_varint(cursor, data)?]),
        2 => {
            let bytes = read_len(cursor, data)?;
            let mut inner = 0usize;
            let mut values = Vec::new();
            while inner < bytes.len() {
                values.push(read_varint(&mut inner, bytes)?);
            }
            Ok(values)
        }
        other => Err(format!("unsupported repeated uint64 wire type {other}")),
    }
}

fn parse_mem_access(data: &[u8]) -> Result<MemAccess, String> {
    let mut cursor = 0usize;
    let mut msg = MemAccess::default();
    while cursor < data.len() {
        let key = read_varint(&mut cursor, data)?;
        let field = key >> 3;
        let wire = key & 7;
        match (field, wire) {
            (1, 0) => msg.inst_addr = read_varint(&mut cursor, data)?,
            (2, 0) => msg.access_addr = read_varint(&mut cursor, data)?,
            (3, 0) => msg.value = read_varint(&mut cursor, data)?,
            (4, 0) => msg.size = read_varint(&mut cursor, data)? as u32,
            (_, wire) => skip_field(wire, &mut cursor, data)?,
        }
    }
    Ok(msg)
}

fn parse_external_return(data: &[u8]) -> Result<ExternalReturn, String> {
    let mut cursor = 0usize;
    let mut msg = ExternalReturn::default();
    while cursor < data.len() {
        let key = read_varint(&mut cursor, data)?;
        let field = key >> 3;
        let wire = key & 7;
        match (field, wire) {
            (1, 0) => msg.return_addr = read_varint(&mut cursor, data)?,
            (2, 0) => msg.return_value = read_varint(&mut cursor, data)?,
            (_, wire) => skip_field(wire, &mut cursor, data)?,
        }
    }
    Ok(msg)
}

fn parse_dynamic_exec_chunk(data: &[u8]) -> Result<DynamicExecChunk, String> {
    let mut cursor = 0usize;
    let mut msg = DynamicExecChunk::default();
    while cursor < data.len() {
        let key = read_varint(&mut cursor, data)?;
        let field = key >> 3;
        let wire = key & 7;
        match (field, wire) {
            (1, 0) => msg.start_addr = read_varint(&mut cursor, data)?,
            (2, 0) => msg.end_addr = read_varint(&mut cursor, data)?,
            (3, 0) => msg.perm = read_varint(&mut cursor, data)? as u32,
            (4, 2) => msg.path = read_string(&mut cursor, data)?,
            (5, 0) => msg.chunk_offset = read_varint(&mut cursor, data)?,
            (6, 2) => msg.data_len = read_len(&mut cursor, data)?.len(),
            (_, wire) => skip_field(wire, &mut cursor, data)?,
        }
    }
    Ok(msg)
}

fn parse_trace_context(data: &[u8]) -> Result<TraceContext, String> {
    let mut cursor = 0usize;
    let mut msg = TraceContext::default();
    while cursor < data.len() {
        let key = read_varint(&mut cursor, data)?;
        let field = key >> 3;
        let wire = key & 7;
        match field {
            1 => msg.x.extend(read_repeated_u64(wire, &mut cursor, data)?),
            2 if wire == 0 => msg.sp = read_varint(&mut cursor, data)?,
            3 if wire == 0 => msg.pc = read_varint(&mut cursor, data)?,
            4 if wire == 0 => msg.nzcv = read_varint(&mut cursor, data)?,
            5 if wire == 0 => msg.tpidr_el0 = read_varint(&mut cursor, data)?,
            6 => msg.q_words += read_repeated_u64(wire, &mut cursor, data)?.len(),
            7 if wire == 0 => msg.fpcr = read_varint(&mut cursor, data)?,
            8 if wire == 0 => msg.fpsr = read_varint(&mut cursor, data)?,
            _ => skip_field(wire, &mut cursor, data)?,
        }
    }
    Ok(msg)
}

fn parse_metadata(data: &[u8]) -> Result<TraceBundleMetadata, String> {
    let mut cursor = 0usize;
    let mut msg = TraceBundleMetadata::default();
    while cursor < data.len() {
        let key = read_varint(&mut cursor, data)?;
        let field = key >> 3;
        let wire = key & 7;
        match (field, wire) {
            (1, 2) => msg.module_path = read_string(&mut cursor, data)?,
            (2, 0) => msg.module_base = read_varint(&mut cursor, data)?,
            (_, wire) => skip_field(wire, &mut cursor, data)?,
        }
    }
    Ok(msg)
}

fn parse_event(data: &[u8]) -> Result<Event, String> {
    let mut cursor = 0usize;
    let mut event = Event::Unknown;
    while cursor < data.len() {
        let key = read_varint(&mut cursor, data)?;
        let field = key >> 3;
        let wire = key & 7;
        event = match (field, wire) {
            (1, 0) => Event::InstructionAddr(read_varint(&mut cursor, data)?),
            (2, 2) => Event::MemAccess(parse_mem_access(read_len(&mut cursor, data)?)?),
            (3, 2) => Event::ExternalReturn(parse_external_return(read_len(&mut cursor, data)?)?),
            (4, 2) => Event::DynamicExecChunk(parse_dynamic_exec_chunk(read_len(&mut cursor, data)?)?),
            (5, 2) => Event::TraceContext(parse_trace_context(read_len(&mut cursor, data)?)?),
            (6, 2) => Event::TraceBundleMetadata(parse_metadata(read_len(&mut cursor, data)?)?),
            (_, wire) => {
                skip_field(wire, &mut cursor, data)?;
                event
            }
        };
    }
    Ok(event)
}

fn format_addr(addr: u64, state: &TraceState) -> String {
    if state.module_base != 0 && addr >= state.module_base {
        format!("0x{addr:016x} (module+0x{:x})", addr - state.module_base)
    } else {
        format!("0x{addr:016x}")
    }
}

fn low_regs(ctx: &TraceContext) -> String {
    let mut text = String::new();
    for idx in 0..8usize {
        let value = ctx.x.get(idx).copied().unwrap_or(0);
        let _ = write!(text, " x{idx}=0x{value:x}");
    }
    let lr = ctx.x.get(30).copied().unwrap_or(0);
    let _ = write!(text, " lr=0x{lr:x}");
    text
}

fn format_event(index: usize, event: &Event, state: &mut TraceState, stats: &mut Stats) -> String {
    stats.total += 1;
    match event {
        Event::InstructionAddr(addr) => {
            stats.instructions += 1;
            format!("{index:06} inst pc={}", format_addr(*addr, state))
        }
        Event::MemAccess(mem) => {
            stats.mem_accesses += 1;
            format!(
                "{index:06} mem  inst={} access=0x{:016x} size={} value=0x{:x}",
                format_addr(mem.inst_addr, state),
                mem.access_addr,
                mem.size,
                mem.value
            )
        }
        Event::ExternalReturn(ret) => {
            stats.external_returns += 1;
            format!(
                "{index:06} ret  pc={} x0=0x{:x}",
                format_addr(ret.return_addr, state),
                ret.return_value
            )
        }
        Event::DynamicExecChunk(chunk) => {
            stats.dynamic_chunks += 1;
            format!(
                "{index:06} dyn  range=0x{:016x}-0x{:016x} perm=0x{:x} offset=0x{:x} data={} path={}",
                chunk.start_addr, chunk.end_addr, chunk.perm, chunk.chunk_offset, chunk.data_len, chunk.path
            )
        }
        Event::TraceContext(ctx) => {
            stats.contexts += 1;
            format!(
                "{index:06} ctx  pc={} sp=0x{:016x} nzcv=0x{:x} tpidr_el0=0x{:x} q_words={}{}",
                format_addr(ctx.pc, state),
                ctx.sp,
                ctx.nzcv,
                ctx.tpidr_el0,
                ctx.q_words,
                low_regs(ctx)
            )
        }
        Event::TraceBundleMetadata(meta) => {
            stats.metadata += 1;
            state.module_path = Some(meta.module_path.clone());
            state.module_base = meta.module_base;
            format!(
                "{index:06} meta module_base=0x{:016x} module_path={}",
                meta.module_base, meta.module_path
            )
        }
        Event::Unknown => {
            stats.unknown += 1;
            format!("{index:06} unknown")
        }
    }
}

fn print_summary(stats: &Stats, state: &TraceState, bytes: usize) {
    println!("summary:");
    println!("  bytes={bytes}");
    println!("  events={}", stats.total);
    println!("  metadata={}", stats.metadata);
    println!("  contexts={}", stats.contexts);
    println!("  instructions={}", stats.instructions);
    println!("  mem_accesses={}", stats.mem_accesses);
    println!("  external_returns={}", stats.external_returns);
    println!("  dynamic_chunks={}", stats.dynamic_chunks);
    println!("  unknown={}", stats.unknown);
    if state.module_base != 0 || state.module_path.is_some() {
        println!(
            "  module=0x{:016x} {}",
            state.module_base,
            state.module_path.as_deref().unwrap_or("")
        );
    }
}

fn run() -> Result<(), String> {
    let options = parse_args()?;
    let data = fs::read(&options.input).map_err(|err| format!("read {} failed: {err}", options.input))?;
    if data.len() < TRACE_BUNDLE_MAGIC.len() || &data[..TRACE_BUNDLE_MAGIC.len()] != TRACE_BUNDLE_MAGIC {
        return Err(format!("{} is not a TRB1 trace bundle", options.input));
    }

    println!("trace_bundle={}", options.input);
    let mut cursor = TRACE_BUNDLE_MAGIC.len();
    let mut index = 0usize;
    let mut printed = 0usize;
    let mut stats = Stats::default();
    let mut state = TraceState::default();

    while cursor < data.len() {
        let event_len = read_varint(&mut cursor, &data)? as usize;
        let end = cursor
            .checked_add(event_len)
            .ok_or_else(|| "event length overflow".to_string())?;
        let event_data = data
            .get(cursor..end)
            .ok_or_else(|| format!("event {index} is truncated"))?;
        cursor = end;

        let event = parse_event(event_data).map_err(|err| format!("decode event {index} failed: {err}"))?;
        let line = format_event(index, &event, &mut state, &mut stats);
        if !options.summary_only && options.limit.map_or(true, |limit| printed < limit) {
            println!("{line}");
            printed += 1;
        }
        index += 1;
    }

    if !options.summary_only && options.limit.is_some_and(|limit| stats.total > limit) {
        println!("... truncated event output at --limit {}", options.limit.unwrap());
    }
    print_summary(&stats, &state, data.len());
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
