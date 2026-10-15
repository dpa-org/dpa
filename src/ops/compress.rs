//! Compression ops: gzip / zlib.

use std::collections::HashMap;
use std::io::{Read, Write};

use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use flate2::write::{DeflateEncoder, ZlibEncoder};
use flate2::{Compress, Compression, Crc, Decompress, FlushCompress, FlushDecompress, Status};

use super::{ArgSpec, Op, StreamingOp};
use crate::i18n;
use std::io::Cursor;

// bzip2 uses libbz2 C bindings (host-only; cfg-gated for wasm32)
#[cfg(not(target_arch = "wasm32"))]
use bzip2::Compression as BzCompression;
#[cfg(not(target_arch = "wasm32"))]
use bzip2::read::{BzDecoder, BzEncoder};

pub fn ops() -> Vec<Op> {
    // `mut` is only needed on non-wasm hosts where bzip2 ops are appended.
    #[allow(unused_mut)]
    let mut v = vec![
        stream_op!(
            "dpa:gzip:compress",
            "codec",
            "op.gzip.compress.desc",
            &[
                ArgSpec {
                    name: "level",
                    required: false,
                    description: "op.gzip.compress.arg.level",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "filename",
                    required: false,
                    description: "op.gzip.compress.arg.filename",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "comment",
                    required: false,
                    description: "op.gzip.compress.arg.comment",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "timestamp",
                    required: false,
                    description: "op.gzip.compress.arg.timestamp",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "os",
                    required: false,
                    description: "op.gzip.compress.arg.os",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "fhcrc",
                    required: false,
                    description: "op.gzip.compress.arg.fhcrc",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            gzip_compress,
            make_gzip_compress
        ),
        stream_op!(
            "dpa:gzip:decompress",
            "codec",
            "op.gzip.decompress.desc",
            &[],
            gzip_decompress,
            make_gzip_decompress
        ),
        stream_op!(
            "dpa:zlib:compress",
            "codec",
            "op.zlib.compress.desc",
            &[ArgSpec {
                name: "level",
                required: false,
                description: "op.zlib.compress.arg.level",
                format: crate::ops::ArgFormat::Utf8,
            }],
            zlib_compress,
            make_zlib_compress
        ),
        stream_op!(
            "dpa:zlib:decompress",
            "codec",
            "op.zlib.decompress.desc",
            &[],
            zlib_decompress,
            make_zlib_decompress
        ),
        // raw containers
        stream_op!(
            "dpa:deflate:compress",
            "codec",
            "op.deflate.compress.desc",
            &[ArgSpec {
                name: "level",
                required: false,
                description: "op.deflate.compress.arg.level",
                format: crate::ops::ArgFormat::Utf8,
            }],
            deflate_compress,
            make_deflate_compress
        ),
        stream_op!(
            "dpa:deflate:decompress",
            "codec",
            "op.deflate.decompress.desc",
            &[],
            deflate_decompress,
            make_deflate_decompress
        ),
        stream_op!(
            "dpa:brotli:compress",
            "codec",
            "op.brotli.compress.desc",
            &[ArgSpec {
                name: "quality",
                required: false,
                description: "op.brotli.compress.arg.quality",
                format: crate::ops::ArgFormat::Utf8,
            }],
            brotli_compress,
            make_brotli_compress
        ),
        stream_op!(
            "dpa:brotli:decompress",
            "codec",
            "op.brotli.decompress.desc",
            &[],
            brotli_decompress,
            make_brotli_decompress
        ),
        // LZMA/XZ (CyberChef LZMA Compress/Decompress parity)
        stream_op!(
            "dpa:lzma:compress",
            "codec",
            "op.lzma.compress.desc",
            &[ArgSpec {
                name: "format",
                required: false,
                description: "op.lzma.compress.arg.format",
                format: crate::ops::ArgFormat::Utf8,
            }],
            lzma_compress,
            make_lzma_compress
        ),
        stream_op!(
            "dpa:lzma:decompress",
            "codec",
            "op.lzma.decompress.desc",
            &[ArgSpec {
                name: "format",
                required: false,
                description: "op.lzma.decompress.arg.format",
                format: crate::ops::ArgFormat::Utf8,
            }],
            lzma_decompress,
            make_lzma_decompress
        ),
    ];
    // bzip2 (libbz2 C bindings — host-only)
    #[cfg(not(target_arch = "wasm32"))]
    v.extend(bzip2_ops());
    v
}

/// bzip2 ops registered only on non-wasm hosts (libbz2 C bindings).
#[cfg(not(target_arch = "wasm32"))]
fn bzip2_ops() -> Vec<Op> {
    vec![
        stream_op!(
            "dpa:bzip2:compress",
            "codec",
            "op.bzip2.compress.desc",
            &[ArgSpec {
                name: "quality",
                required: false,
                description: "op.bzip2.compress.arg.quality",
                format: crate::ops::ArgFormat::Utf8,
            }],
            bzip2_compress,
            make_bzip2_compress
        ),
        stream_op!(
            "dpa:bzip2:decompress",
            "codec",
            "op.bzip2.decompress.desc",
            &[],
            bzip2_decompress,
            make_bzip2_decompress
        ),
    ]
}

/// Parse a flate2 compression level (0-9). Missing arg keeps the library
/// default (6), preserving legacy output byte-for-byte.
fn parse_level(args: &HashMap<String, String>, key: &str) -> anyhow::Result<u32> {
    match args.get(key) {
        None => Ok(6),
        Some(raw) => {
            let level: u32 = raw
                .parse()
                .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.bad_level", &[raw.as_str()])))?;
            if level > 9 {
                anyhow::bail!("{}", i18n::tf("err.bad_level", &[raw.as_str()]));
            }
            Ok(level)
        }
    }
}

/// Parse a Brotli quality (0-11). Missing arg keeps the encoder default (11),
/// preserving legacy output byte-for-byte.
fn parse_quality(args: &HashMap<String, String>) -> anyhow::Result<i32> {
    match args.get("quality") {
        None => Ok(11),
        Some(raw) => {
            let q: i32 = raw
                .parse()
                .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.bad_quality", &[raw.as_str()])))?;
            if !(0..=11).contains(&q) {
                anyhow::bail!("{}", i18n::tf("err.bad_quality", &[raw.as_str()]));
            }
            Ok(q)
        }
    }
}

/// Gzip header options mirroring CyberChef Gzip (Filename / Comment /
/// Timestamp / Operating system). `None` fields keep the default empty header.
struct GzipHeaderOpts {
    filename: Option<String>,
    comment: Option<String>,
    mtime: u32,
    os: u8,
    fhcrc: bool,
}

fn parse_gzip_header_opts(args: &HashMap<String, String>) -> anyhow::Result<GzipHeaderOpts> {
    let filename = args.get("filename").filter(|s| !s.is_empty()).cloned();
    let comment = args.get("comment").filter(|s| !s.is_empty()).cloned();
    let mtime = match args.get("timestamp").filter(|s| !s.is_empty()) {
        Some(ts) => ts
            .parse()
            .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.bad_timestamp", &[ts.as_str()])))?,
        None => 0,
    };
    let os = match args.get("os").filter(|s| !s.is_empty()) {
        Some(v) => v
            .parse()
            .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.bad_os", &[v.as_str()])))?,
        None => 0xff,
    };
    let fhcrc = match args.get("fhcrc").filter(|s| !s.is_empty()) {
        Some(v) => crate::ops::parse_bool(v)?,
        None => false,
    };
    Ok(GzipHeaderOpts {
        filename,
        comment,
        mtime,
        os,
        fhcrc,
    })
}

/// Build the 10-byte gzip header (plus optional FNAME / FCOMMENT / FHCRC fields) by
/// hand, matching flate2's GzBuilder byte layout so streaming and memory paths
/// produce identical output. When `fhcrc` is set, the 2-byte CRC16 (low 16 bits
/// of the RFC 1952 header CRC32, little-endian) is appended after the optional
/// fields, mirroring CyberChef's "Include file checksum" flag.
fn build_gzip_header(opts: &GzipHeaderOpts) -> Vec<u8> {
    let mut flg = 0u8;
    // gzip header flags: bit1 = FHCRC, bit3 = FNAME, bit4 = FCOMMENT (RFC 1952)
    if opts.fhcrc {
        flg |= 0x02;
    }
    if opts.filename.is_some() {
        flg |= 0x08;
    }
    if opts.comment.is_some() {
        flg |= 0x10;
    }
    let mut h = vec![0x1f, 0x8b, 0x08, flg, 0, 0, 0, 0, 0x00, opts.os];
    h[4..8].copy_from_slice(&opts.mtime.to_le_bytes());
    if let Some(f) = &opts.filename {
        h.extend_from_slice(f.as_bytes());
        h.push(0);
    }
    if let Some(c) = &opts.comment {
        h.extend_from_slice(c.as_bytes());
        h.push(0);
    }
    if opts.fhcrc {
        let mut crc = Crc::new();
        crc.update(&h);
        let crc16 = crc.sum() as u16;
        h.extend_from_slice(&crc16.to_le_bytes());
    }
    h
}

fn gzip_compress(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let level = parse_level(args, "level")?;
    let opts = parse_gzip_header_opts(args)?;
    if opts.fhcrc {
        // flate2's GzBuilder has no FHCRC write path, so assemble the header,
        // raw DEFLATE body and 8-byte trailer by hand (identical to the
        // streaming path, which already writes FHCRC).
        let mut out = build_gzip_header(&opts);
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::new(level));
        enc.write_all(input)?;
        out.extend_from_slice(&enc.finish()?);
        let mut crc = Crc::new();
        crc.update(input);
        out.extend_from_slice(&crc.sum().to_le_bytes());
        out.extend_from_slice(&(input.len() as u32).to_le_bytes());
        return Ok(out);
    }
    let mut builder = flate2::GzBuilder::new();
    if let Some(name) = &opts.filename {
        let cstr = std::ffi::CString::new(name.as_str())
            .map_err(|_| anyhow::anyhow!("{}", i18n::t("err.gzip_filename_nul")))?;
        builder = builder.filename(cstr);
    }
    if let Some(comment) = &opts.comment {
        builder = builder.comment(comment.as_bytes());
    }
    if opts.mtime != 0 {
        builder = builder.mtime(opts.mtime);
    }
    if opts.os != 0xff {
        builder = builder.operating_system(opts.os);
    }
    let mut enc = builder.write(Vec::new(), Compression::new(level));
    enc.write_all(input)?;
    enc.finish().map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.gzip_compress", &[e.to_string().as_str()])
        )
    })
}

fn gzip_decompress(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let mut dec = GzDecoder::new(input);
    let mut out = Vec::new();
    dec.read_to_end(&mut out).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.gzip_decompress", &[e.to_string().as_str()])
        )
    })?;
    Ok(out)
}

fn zlib_compress(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let level = parse_level(args, "level")?;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::new(level));
    enc.write_all(input)?;
    enc.finish().map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.zlib_compress", &[e.to_string().as_str()])
        )
    })
}

fn zlib_decompress(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let mut dec = ZlibDecoder::new(input);
    let mut out = Vec::new();
    dec.read_to_end(&mut out).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.zlib_decompress", &[e.to_string().as_str()])
        )
    })?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Streaming implementation
// Note: the default miniz backend has no gzip wrapper (zlib/raw deflate only), so the gzip
// 10-byte header, optional fields and 8-byte trailer (CRC32 + ISIZE) are maintained manually here;
// zlib uses flate2's Compress/Decompress directly (automatic header and Adler-32).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
struct GzipCompressStream {
    comp: Compress,
    crc: Crc,
    total_in: u64,
    header_sent: bool,
    header_opts: GzipHeaderOpts,
}

fn make_gzip_compress(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let level = parse_level(args, "level")?;
    let header_opts = parse_gzip_header_opts(args)?;
    Ok(Box::new(GzipCompressStream {
        comp: Compress::new(Compression::new(level), false),
        crc: Crc::new(),
        total_in: 0,
        header_sent: false,
        header_opts,
    }))
}

/// Human-readable reason for a miniz `Status` that made no progress
/// (the `Status` enum has no `Display` impl; Debug output is not stable UI text).
fn status_reason(s: Status) -> &'static str {
    match s {
        Status::Ok => "no progress",
        Status::BufError => "output buffer full",
        Status::StreamEnd => "unexpected stream end",
    }
}

/// Feed a whole chunk into the compressor and return the incremental output.
fn pump_compress(comp: &mut Compress, input: &mut &[u8], out: &mut Vec<u8>) -> anyhow::Result<()> {
    loop {
        // compress_vec only writes into spare capacity and never grows the Vec; reserve first.
        out.reserve(64 * 1024);
        let before = comp.total_in();
        let status = comp
            .compress_vec(input, out, FlushCompress::None)
            .map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.compress_failed", &[e.to_string().as_str()])
                )
            })?;
        let consumed = (comp.total_in() - before) as usize;
        if consumed == 0 && status != Status::StreamEnd {
            if status == Status::BufError {
                // miniz requires enough space for the flushed output at once; keep growing while it is short.
                out.reserve(out.capacity().max(64 * 1024));
                continue;
            }
            anyhow::bail!(
                "{}",
                i18n::tf("err.compressor_stuck", &[status_reason(status)])
            );
        }
        *input = &input[consumed..];
        if status == Status::StreamEnd || input.is_empty() {
            break;
        }
    }
    Ok(())
}

impl StreamingOp for GzipCompressStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::new();
        if !self.header_sent {
            out.extend_from_slice(&build_gzip_header(&self.header_opts));
            self.header_sent = true;
        }
        self.crc.update(chunk);
        self.total_in += chunk.len() as u64;
        let mut rem = chunk;
        pump_compress(&mut self.comp, &mut rem, &mut out)?;
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let empty: &[u8] = &[];
            let status = self
                .comp
                .compress_vec(empty, &mut out, FlushCompress::Finish)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "{}",
                        i18n::tf("err.gzip_compress", &[e.to_string().as_str()])
                    )
                })?;
            if status == Status::StreamEnd {
                break;
            }
            if status == Status::BufError {
                out.reserve(out.capacity().max(64 * 1024));
                continue;
            }
        }
        out.extend_from_slice(&self.crc.sum().to_le_bytes());
        out.extend_from_slice(&(self.total_in as u32).to_le_bytes());
        Ok(out)
    }
}

/// Streaming zlib compress: Compress::new(_, true) emits the zlib header and trailer automatically.
struct ZlibCompressStream {
    comp: Compress,
}

fn make_zlib_compress(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let level = parse_level(args, "level")?;
    Ok(Box::new(ZlibCompressStream {
        comp: Compress::new(Compression::new(level), true),
    }))
}

impl StreamingOp for ZlibCompressStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut rem = chunk;
        pump_compress(&mut self.comp, &mut rem, &mut out)?;
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            out.reserve(64 * 1024);
            let empty: &[u8] = &[];
            let status = self
                .comp
                .compress_vec(empty, &mut out, FlushCompress::Finish)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "{}",
                        i18n::tf("err.zlib_compress", &[e.to_string().as_str()])
                    )
                })?;
            if status == Status::StreamEnd {
                break;
            }
            if status == Status::BufError {
                out.reserve(out.capacity().max(64 * 1024));
                continue;
            }
        }
        Ok(out)
    }
}

/// gzip header parsing states: RFC 1952 fixed 10 bytes + optional fields (FEXTRA/FNAME/FCOMMENT/FHCRC).
#[derive(Clone, Copy)]
enum GzHeaderState {
    Init,
    ExtraLen,
    Extra(usize),
    Name,
    Comment,
    Crc,
    Complete,
}

/// Streaming gzip decompress: parse header -> raw inflate -> validate the 8-byte trailer (CRC32 + ISIZE).
/// Matches in-memory read::GzDecoder: only the first member is processed; trailing bytes are ignored.
struct GzipDecompressStream {
    dec: Decompress,
    crc: Crc,
    total_out: u64,
    header: GzHeaderState,
    remaining_flags: u8,
    hbuf: Vec<u8>,
    xlen_buf: Vec<u8>,
    trailer: Vec<u8>,
    phase: GzPhase,
}

#[derive(Clone, Copy, PartialEq)]
enum GzPhase {
    Header,
    Body,
    Trailer,
    Done,
}

fn make_gzip_decompress(_args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(GzipDecompressStream {
        dec: Decompress::new(false),
        crc: Crc::new(),
        total_out: 0,
        header: GzHeaderState::Init,
        remaining_flags: 0,
        hbuf: Vec::new(),
        xlen_buf: Vec::new(),
        trailer: Vec::new(),
        phase: GzPhase::Header,
    }))
}

impl GzipDecompressStream {
    /// Consume header bytes; returns (consumed count, whether the header is complete).
    fn feed_header(&mut self, data: &[u8]) -> anyhow::Result<(usize, bool)> {
        let mut i = 0usize;
        while i < data.len() {
            let b = data[i];
            match self.header {
                GzHeaderState::Init => {
                    self.hbuf.push(b);
                    i += 1;
                    if self.hbuf.len() == 10 {
                        if self.hbuf[0] != 0x1f
                            || self.hbuf[1] != 0x8b
                            || self.hbuf[2] != 0x08
                            || (self.hbuf[3] & 0xe0) != 0
                        {
                            anyhow::bail!("{}", i18n::t("err.gzip_bad_header"));
                        }
                        self.remaining_flags = self.hbuf[3] & 0x1e;
                        self.header = next_header_state(self.remaining_flags);
                        if matches!(self.header, GzHeaderState::Complete) {
                            return Ok((i, true));
                        }
                    }
                }
                GzHeaderState::ExtraLen => {
                    self.xlen_buf.push(b);
                    i += 1;
                    if self.xlen_buf.len() == 2 {
                        let xlen =
                            u16::from_le_bytes([self.xlen_buf[0], self.xlen_buf[1]]) as usize;
                        self.xlen_buf.clear();
                        self.remaining_flags &= !0x04;
                        self.header = if xlen == 0 {
                            next_header_state(self.remaining_flags)
                        } else {
                            GzHeaderState::Extra(xlen)
                        };
                        if matches!(self.header, GzHeaderState::Complete) {
                            return Ok((i, true));
                        }
                    }
                }
                GzHeaderState::Extra(n) => {
                    i += 1;
                    self.header = if n <= 1 {
                        next_header_state(self.remaining_flags)
                    } else {
                        GzHeaderState::Extra(n - 1)
                    };
                    if matches!(self.header, GzHeaderState::Complete) {
                        return Ok((i, true));
                    }
                }
                GzHeaderState::Name | GzHeaderState::Comment => {
                    i += 1;
                    if b == 0 {
                        let done_extra = matches!(self.header, GzHeaderState::Name);
                        self.remaining_flags &= if done_extra { !0x08 } else { !0x10 };
                        self.header = next_header_state(self.remaining_flags);
                        if matches!(self.header, GzHeaderState::Complete) {
                            return Ok((i, true));
                        }
                    }
                }
                GzHeaderState::Crc => {
                    i += 1;
                    if self.xlen_buf.len() < 2 {
                        self.xlen_buf.push(b);
                    }
                    if self.xlen_buf.len() == 2 {
                        self.xlen_buf.clear();
                        self.remaining_flags &= !0x02;
                        self.header = next_header_state(self.remaining_flags);
                        if matches!(self.header, GzHeaderState::Complete) {
                            return Ok((i, true));
                        }
                    }
                }
                GzHeaderState::Complete => return Ok((i, true)),
            }
        }
        Ok((i, matches!(self.header, GzHeaderState::Complete)))
    }
}

fn next_header_state(flags: u8) -> GzHeaderState {
    if flags & 0x04 != 0 {
        GzHeaderState::ExtraLen
    } else if flags & 0x08 != 0 {
        GzHeaderState::Name
    } else if flags & 0x10 != 0 {
        GzHeaderState::Comment
    } else if flags & 0x02 != 0 {
        GzHeaderState::Crc
    } else {
        GzHeaderState::Complete
    }
}

impl StreamingOp for GzipDecompressStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut rest = chunk;
        while !rest.is_empty() {
            match self.phase {
                GzPhase::Header => {
                    let (consumed, done) = self.feed_header(rest)?;
                    rest = &rest[consumed..];
                    if done {
                        self.phase = GzPhase::Body;
                    }
                }
                GzPhase::Body => {
                    let mut rem = rest;
                    loop {
                        out.reserve(64 * 1024);
                        let in_before = self.dec.total_in();
                        let out_before = self.dec.total_out();
                        let status = self
                            .dec
                            .decompress_vec(rem, &mut out, FlushDecompress::None)
                            .map_err(|e| {
                                anyhow::anyhow!(
                                    "{}",
                                    i18n::tf("err.gzip_decompress", &[e.to_string().as_str()])
                                )
                            })?;
                        let consumed = (self.dec.total_in() - in_before) as usize;
                        let produced = (self.dec.total_out() - out_before) as usize;
                        if consumed == 0 && produced == 0 && status != Status::StreamEnd {
                            if status == Status::BufError {
                                out.reserve(out.capacity().max(64 * 1024));
                                continue;
                            }
                            anyhow::bail!(
                                "{}",
                                i18n::tf("err.decompressor_stuck", &[status_reason(status)])
                            );
                        }
                        if produced > 0 {
                            let start = out.len() - produced;
                            self.crc.update(&out[start..]);
                            self.total_out += produced as u64;
                        }
                        rem = &rem[consumed..];
                        if status == Status::StreamEnd {
                            self.phase = GzPhase::Trailer;
                            rest = rem;
                            break;
                        }
                        if rem.is_empty() {
                            rest = rem;
                            break;
                        }
                    }
                    if self.phase == GzPhase::Body {
                        break;
                    }
                }
                GzPhase::Trailer => {
                    let need = 8usize.saturating_sub(self.trailer.len());
                    let take = need.min(rest.len());
                    self.trailer.extend_from_slice(&rest[..take]);
                    if self.trailer.len() == 8 {
                        let crc =
                            u32::from_le_bytes(self.trailer[0..4].try_into().expect("4 bytes"));
                        let isize =
                            u32::from_le_bytes(self.trailer[4..8].try_into().expect("4 bytes"));
                        if crc != self.crc.sum() {
                            anyhow::bail!("{}", i18n::t("err.gzip_crc"));
                        }
                        if isize != self.total_out as u32 {
                            anyhow::bail!("{}", i18n::t("err.gzip_len"));
                        }
                        self.phase = GzPhase::Done;
                        self.trailer.clear();
                    }
                    break;
                }
                GzPhase::Done => break,
            }
        }
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        match self.phase {
            GzPhase::Done => Ok(Vec::new()),
            GzPhase::Trailer => anyhow::bail!("{}", i18n::t("err.gzip_incomplete_trailer")),
            _ => anyhow::bail!("{}", i18n::t("err.gzip_incomplete")),
        }
    }
}

/// Streaming zlib decompress: Decompress::new(true) parses the zlib header and validates Adler-32.
struct ZlibDecompressStream {
    dec: Decompress,
    saw_end: bool,
}

fn make_zlib_decompress(_args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(ZlibDecompressStream {
        dec: Decompress::new(true),
        saw_end: false,
    }))
}

impl StreamingOp for ZlibDecompressStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut rem = chunk;
        while !rem.is_empty() && !self.saw_end {
            out.reserve(64 * 1024);
            let in_before = self.dec.total_in();
            let status = self
                .dec
                .decompress_vec(rem, &mut out, FlushDecompress::None)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "{}",
                        i18n::tf("err.zlib_decompress", &[e.to_string().as_str()])
                    )
                })?;
            let consumed = (self.dec.total_in() - in_before) as usize;
            if consumed == 0 && status != Status::StreamEnd {
                if status == Status::BufError {
                    out.reserve(out.capacity().max(64 * 1024));
                    continue;
                }
                anyhow::bail!(
                    "{}",
                    i18n::tf("err.decompressor_stuck", &[status_reason(status)])
                );
            }
            rem = &rem[consumed..];
            if status == Status::StreamEnd {
                self.saw_end = true;
            }
        }
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        if self.saw_end {
            Ok(Vec::new())
        } else {
            anyhow::bail!("{}", i18n::t("err.zlib_incomplete"))
        }
    }
}

// ---------------------------------------------------------------------------
// Raw DEFLATE: RFC 1951 with no zlib/gzip wrapper. Streaming
// path is Compress/Decompress with wrapper=false; memory path uses the
// flate2 DeflateEncoder/DeflateDecoder convenience readers/writers.
// ---------------------------------------------------------------------------

struct DeflateCompressStream {
    comp: Compress,
}

fn make_deflate_compress(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let level = parse_level(args, "level")?;
    Ok(Box::new(DeflateCompressStream {
        comp: Compress::new(Compression::new(level), false),
    }))
}

impl StreamingOp for DeflateCompressStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut rem = chunk;
        pump_compress(&mut self.comp, &mut rem, &mut out)?;
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            out.reserve(64 * 1024);
            let empty: &[u8] = &[];
            let status = self
                .comp
                .compress_vec(empty, &mut out, FlushCompress::Finish)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "{}",
                        i18n::tf("err.deflate_compress", &[e.to_string().as_str()])
                    )
                })?;
            if status == Status::StreamEnd {
                break;
            }
            if status == Status::BufError {
                out.reserve(out.capacity().max(64 * 1024));
                continue;
            }
        }
        Ok(out)
    }
}

struct DeflateDecompressStream {
    dec: Decompress,
    saw_end: bool,
}

fn make_deflate_decompress(
    _args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(DeflateDecompressStream {
        dec: Decompress::new(false),
        saw_end: false,
    }))
}

impl StreamingOp for DeflateDecompressStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut rem = chunk;
        while !rem.is_empty() && !self.saw_end {
            out.reserve(64 * 1024);
            let in_before = self.dec.total_in();
            let status = self
                .dec
                .decompress_vec(rem, &mut out, FlushDecompress::None)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "{}",
                        i18n::tf("err.deflate_decompress", &[e.to_string().as_str()])
                    )
                })?;
            let consumed = (self.dec.total_in() - in_before) as usize;
            if consumed == 0 && status != Status::StreamEnd {
                if status == Status::BufError {
                    out.reserve(out.capacity().max(64 * 1024));
                    continue;
                }
                anyhow::bail!(
                    "{}",
                    i18n::tf("err.decompressor_stuck", &[status_reason(status)])
                );
            }
            rem = &rem[consumed..];
            if status == Status::StreamEnd {
                self.saw_end = true;
            }
        }
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        if self.saw_end {
            Ok(Vec::new())
        } else {
            anyhow::bail!("{}", i18n::t("err.deflate_incomplete"))
        }
    }
}

fn deflate_compress(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let level = parse_level(args, "level")?;
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::new(level));
    enc.write_all(input)?;
    enc.finish().map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.deflate_compress", &[e.to_string().as_str()])
        )
    })
}

fn deflate_decompress(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let mut dec = DeflateDecoder::new(input);
    let mut out = Vec::new();
    dec.read_to_end(&mut out).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.deflate_decompress", &[e.to_string().as_str()])
        )
    })?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Brotli: RFC 7932 via the `brotli` crate. The streaming path
// buffers input and compresses once at finish; output matches the memory path.
// ---------------------------------------------------------------------------

enum BrotliMode {
    Compress,
    Decompress,
}

struct BrotliBufferStream {
    mode: BrotliMode,
    buf: Vec<u8>,
    quality: i32,
}

fn make_brotli_compress(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let quality = parse_quality(args)?;
    Ok(Box::new(BrotliBufferStream {
        mode: BrotliMode::Compress,
        buf: Vec::new(),
        quality,
    }))
}

fn make_brotli_decompress(_args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(BrotliBufferStream {
        mode: BrotliMode::Decompress,
        buf: Vec::new(),
        quality: 0,
    }))
}

impl StreamingOp for BrotliBufferStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        match self.mode {
            BrotliMode::Compress => brotli_compress_with(&self.buf, self.quality),
            BrotliMode::Decompress => brotli_decompress(&self.buf, &HashMap::new()),
        }
    }
}

fn brotli_compress(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let quality = parse_quality(args)?;
    brotli_compress_with(input, quality)
}

fn brotli_compress_with(input: &[u8], quality: i32) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut reader = input;
    let params = brotli::enc::BrotliEncoderParams {
        quality,
        ..Default::default()
    };
    brotli::enc::BrotliCompress(&mut reader, &mut out, &params).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.brotli_compress", &[e.to_string().as_str()])
        )
    })?;
    Ok(out)
}

fn brotli_decompress(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut reader = input;
    brotli::BrotliDecompress(&mut reader, &mut out).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.brotli_decompress", &[e.to_string().as_str()])
        )
    })?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// LZMA / XZ (lzma-rs, pure Rust) + bzip2 (bzip2-rs, pure Rust)
// ---------------------------------------------------------------------------

enum LzmaFormat {
    Xz,
    Lzma,
}

fn parse_lzma_format(args: &HashMap<String, String>) -> anyhow::Result<LzmaFormat> {
    match args.get("format").map(|s| s.as_str()).unwrap_or("xz") {
        "xz" => Ok(LzmaFormat::Xz),
        "lzma" => Ok(LzmaFormat::Lzma),
        other => anyhow::bail!("{}", i18n::tf("err.lzma.format", &[other])),
    }
}

struct LzmaBufferStream {
    compress: bool,
    format: LzmaFormat,
    buf: Vec<u8>,
}

fn make_lzma_compress(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(LzmaBufferStream {
        compress: true,
        format: parse_lzma_format(args)?,
        buf: Vec::new(),
    }))
}

fn make_lzma_decompress(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(LzmaBufferStream {
        compress: false,
        format: parse_lzma_format(args)?,
        buf: Vec::new(),
    }))
}

impl StreamingOp for LzmaBufferStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let input = std::mem::take(&mut self.buf);
        if self.compress {
            lzma_compress(&input, &map_format(&self.format))
        } else {
            lzma_decompress(&input, &map_format(&self.format))
        }
    }
}

fn map_format(f: &LzmaFormat) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert(
        "format".to_string(),
        match f {
            LzmaFormat::Xz => "xz",
            LzmaFormat::Lzma => "lzma",
        }
        .to_string(),
    );
    m
}

fn lzma_compress(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let format = parse_lzma_format(args)?;
    let mut out = Vec::new();
    let mut reader = Cursor::new(input);
    let res = match format {
        LzmaFormat::Xz => lzma_rs::xz_compress(&mut reader, &mut out),
        LzmaFormat::Lzma => lzma_rs::lzma_compress(&mut reader, &mut out),
    };
    res.map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.lzma_compress", &[e.to_string().as_str()])
        )
    })?;
    Ok(out)
}

fn lzma_decompress(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let format = parse_lzma_format(args)?;
    let mut out = Vec::new();
    let mut reader = Cursor::new(input);
    let res = match format {
        LzmaFormat::Xz => lzma_rs::xz_decompress(&mut reader, &mut out),
        LzmaFormat::Lzma => lzma_rs::lzma_decompress(&mut reader, &mut out),
    };
    res.map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.lzma_decompress", &[e.to_string().as_str()])
        )
    })?;
    Ok(out)
}

// bzip2: host-only (libbz2 C bindings); memory-path buffers to the end.
#[cfg(not(target_arch = "wasm32"))]
fn bzip2_compress(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let quality = parse_bzip2_quality(args)?;
    let reader = Cursor::new(input);
    let mut enc = BzEncoder::new(reader, BzCompression::new(quality as u32));
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut enc, &mut out).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.bzip2_compress", &[e.to_string().as_str()])
        )
    })?;
    Ok(out)
}

#[cfg(not(target_arch = "wasm32"))]
fn parse_bzip2_quality(args: &HashMap<String, String>) -> anyhow::Result<i32> {
    match args.get("quality") {
        None => Ok(9),
        Some(raw) => {
            let q: i32 = raw
                .parse()
                .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.bad_quality", &[raw.as_str()])))?;
            if !(1..=9).contains(&q) {
                anyhow::bail!("{}", i18n::tf("err.bad_quality", &[raw.as_str()]));
            }
            Ok(q)
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn bzip2_decompress(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let reader = Cursor::new(input);
    let mut dec = BzDecoder::new(reader);
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut dec, &mut out).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.bzip2_decompress", &[e.to_string().as_str()])
        )
    })?;
    Ok(out)
}

#[cfg(not(target_arch = "wasm32"))]
struct Bzip2BufferStream {
    compress: bool,
    quality: i32,
    buf: Vec<u8>,
}

#[cfg(not(target_arch = "wasm32"))]
fn make_bzip2_compress(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(Bzip2BufferStream {
        compress: true,
        quality: parse_bzip2_quality(args)?,
        buf: Vec::new(),
    }))
}

#[cfg(not(target_arch = "wasm32"))]
fn make_bzip2_decompress(_args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(Bzip2BufferStream {
        compress: false,
        quality: 0,
        buf: Vec::new(),
    }))
}

#[cfg(not(target_arch = "wasm32"))]
impl StreamingOp for Bzip2BufferStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let input = std::mem::take(&mut self.buf);
        if self.compress {
            let mut m = HashMap::new();
            m.insert("quality".to_string(), self.quality.to_string());
            bzip2_compress(&input, &m)
        } else {
            bzip2_decompress(&input, &HashMap::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gzip_roundtrip() {
        let data = b"Hello, dpa! Hello, dpa! Hello, dpa!";
        let enc = gzip_compress(data, &HashMap::new()).unwrap();
        // gzip magic 1f 8b
        assert_eq!(&enc[..2], &[0x1f, 0x8b]);
        let dec = gzip_decompress(&enc, &HashMap::new()).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn gzip_header_options() {
        let data = b"payload";
        let mut args = HashMap::new();
        args.insert("filename".into(), "notes.txt".into());
        args.insert("comment".into(), "generated by dpa".into());
        args.insert("timestamp".into(), "1700000000".into());
        args.insert("os".into(), "3".into());
        let enc = gzip_compress(data, &args).unwrap();
        let mut dec = flate2::read::GzDecoder::new(&enc[..]);
        let header = dec.header().expect("gzip header");
        assert_eq!(header.filename(), Some(b"notes.txt".as_slice()));
        assert_eq!(header.comment(), Some(b"generated by dpa".as_slice()));
        assert_eq!(header.mtime(), 1_700_000_000);
        assert_eq!(header.operating_system(), 3);
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut dec, &mut out).unwrap();
        assert_eq!(out, data);

        // streaming path emits the identical header bytes for the same opts
        let mut stream = make_gzip_compress(&args).unwrap();
        let mut sbuf = Vec::new();
        sbuf.extend_from_slice(&stream.write(data).unwrap());
        sbuf.extend_from_slice(&stream.finish().unwrap());
        assert_eq!(sbuf, enc);

        // invalid values are rejected
        let mut bad = HashMap::new();
        bad.insert("timestamp".into(), "abc".into());
        assert!(gzip_compress(data, &bad).is_err());
        let mut bad = HashMap::new();
        bad.insert("os".into(), "300".into());
        assert!(gzip_compress(data, &bad).is_err());
        let mut bad = HashMap::new();
        bad.insert("filename".into(), "a\0b".into());
        assert!(gzip_compress(data, &bad).is_err());
    }

    #[test]
    fn gzip_fhcrc() {
        // Reference vector: empty optional fields -> header 1f 8b 08 02 00 00 00 00 00 ff,
        // CRC16 = low 16 bits of header CRC32 = 0x90c9 (little-endian bytes 90 c9).
        let data = b"payload";
        let mut args = HashMap::new();
        args.insert("fhcrc".into(), "true".into());
        let enc = gzip_compress(data, &args).unwrap();
        // FLG byte (index 3) has FHCRC bit set
        assert_eq!(enc[3] & 0x02, 0x02);
        // CRC16 field follows the 10-byte fixed header (no FNAME/FCOMMENT here)
        assert_eq!(&enc[10..12], &[0x90, 0xc9]);
        // 1/0 aliases and yes are accepted
        for v in ["1", "yes"] {
            let mut a = HashMap::new();
            a.insert("fhcrc".into(), v.into());
            assert_eq!(gzip_compress(data, &a).unwrap()[3] & 0x02, 0x02);
        }
        // flate2's decoder verifies FHCRC and round-trips the body
        let mut dec = flate2::read::GzDecoder::new(&enc[..]);
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut dec, &mut out).unwrap();
        assert_eq!(out, data);

        // fhcrc + optional fields: CRC16 covers the whole header incl. FNAME/FCOMMENT
        let mut args2 = HashMap::new();
        args2.insert("filename".into(), "a.txt".into());
        args2.insert("comment".into(), "hi".into());
        args2.insert("fhcrc".into(), "true".into());
        let enc2 = gzip_compress(data, &args2).unwrap();
        assert_eq!(enc2[3] & 0x02, 0x02);
        let hdr_len = 10 + b"a.txt".len() + 1 + b"hi".len() + 1;
        let expect = build_gzip_header(&parse_gzip_header_opts(&args2).unwrap());
        assert_eq!(&enc2[..hdr_len + 2], &expect[..]);

        // streaming path emits identical bytes
        let mut stream = make_gzip_compress(&args2).unwrap();
        let mut sbuf = Vec::new();
        sbuf.extend_from_slice(&stream.write(data).unwrap());
        sbuf.extend_from_slice(&stream.finish().unwrap());
        assert_eq!(sbuf, enc2);

        // invalid boolean is rejected
        let mut bad = HashMap::new();
        bad.insert("fhcrc".into(), "maybe".into());
        assert!(gzip_compress(data, &bad).is_err());

        // fhcrc=false keeps the legacy GzBuilder path byte-for-byte
        let plain = gzip_compress(data, &HashMap::new()).unwrap();
        assert_eq!(plain[3] & 0x02, 0);
        let mut a = HashMap::new();
        a.insert("fhcrc".into(), "false".into());
        assert_eq!(gzip_compress(data, &a).unwrap(), plain);
    }

    #[test]
    fn zlib_roundtrip() {
        let data = b"Hello, dpa! Hello, dpa! Hello, dpa!";
        let enc = zlib_compress(data, &HashMap::new()).unwrap();
        // zlib header: 0x78 0x9c (default level)
        assert_eq!(&enc[..2], &[0x78, 0x9c]);
        let dec = zlib_decompress(&enc, &HashMap::new()).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn decompress_rejects_garbage() {
        assert!(gzip_decompress(b"not gzip", &HashMap::new()).is_err());
    }

    #[test]
    fn deflate_roundtrip() {
        let data = b"Raw DEFLATE roundtrip payload with some repetition repetition repetition!";
        let enc = deflate_compress(data, &HashMap::new()).unwrap();
        // Raw deflate must NOT start with the gzip magic.
        assert_ne!(&enc[..2], &[0x1f, 0x8b]);
        let dec = deflate_decompress(&enc, &HashMap::new()).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn deflate_stream_matches_memory() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let mut h = make_deflate_compress(&HashMap::new()).unwrap();
        let mut acc = Vec::new();
        for c in data.chunks(7) {
            acc.extend(h.write(c).unwrap());
        }
        acc.extend(h.finish().unwrap());
        assert_eq!(acc, deflate_compress(&data, &HashMap::new()).unwrap());

        let mut d = make_deflate_decompress(&HashMap::new()).unwrap();
        let mut acc2 = Vec::new();
        for c in acc.chunks(11) {
            acc2.extend(d.write(c).unwrap());
        }
        acc2.extend(d.finish().unwrap());
        assert_eq!(acc2, data);
    }

    #[test]
    fn brotli_roundtrip() {
        let data = b"Brotli roundtrip payload, brotli is great at text compression!";
        let enc = brotli_compress(data, &HashMap::new()).unwrap();
        let dec = brotli_decompress(&enc, &HashMap::new()).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn brotli_stream_matches_memory() {
        let data: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
        let mut h = make_brotli_compress(&HashMap::new()).unwrap();
        let mut acc = Vec::new();
        for c in data.chunks(9) {
            acc.extend(h.write(c).unwrap());
        }
        acc.extend(h.finish().unwrap());
        assert_eq!(acc, brotli_compress(&data, &HashMap::new()).unwrap());

        let mut d = make_brotli_decompress(&HashMap::new()).unwrap();
        let mut acc2 = Vec::new();
        for c in acc.chunks(13) {
            acc2.extend(d.write(c).unwrap());
        }
        acc2.extend(d.finish().unwrap());
        assert_eq!(acc2, data);
    }

    #[test]
    fn brotli_rejects_garbage() {
        assert!(brotli_decompress(b"not brotli", &HashMap::new()).is_err());
    }

    fn level_args(level: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("level".to_string(), level.to_string());
        m
    }

    #[test]
    fn gzip_level_changes_output_and_roundtrips() {
        let data = b"level test payload with repeated repeated repeated content!";
        let l1 = gzip_compress(data, &level_args("1")).unwrap();
        let l9 = gzip_compress(data, &level_args("9")).unwrap();
        assert_ne!(
            l1, l9,
            "different levels must produce different gzip output"
        );
        // Default (no arg) roundtrips like level 6; only the header XFL flag
        // may differ between Compression::default() and explicit new(6).
        let def = gzip_compress(data, &HashMap::new()).unwrap();
        assert_eq!(gzip_decompress(&def, &HashMap::new()).unwrap(), data);
        for (enc, level) in [(&l1, "1"), (&l9, "9")] {
            assert_eq!(gzip_decompress(enc, &HashMap::new()).unwrap(), data);
            // Streaming factory honours the same level and matches memory.
            let mut s = make_gzip_compress(&level_args(level)).unwrap();
            let mut acc = Vec::new();
            for c in data.chunks(5) {
                acc.extend(s.write(c).unwrap());
            }
            acc.extend(s.finish().unwrap());
            // The XFL header flag may differ between the streaming and memory
            // writers even at the same level; the payload must match.
            assert_eq!(gzip_decompress(&acc, &HashMap::new()).unwrap(), data);
            assert_eq!(
                gzip_decompress(&acc, &HashMap::new()).unwrap(),
                gzip_decompress(enc, &HashMap::new()).unwrap()
            );
        }
        // Invalid levels rejected by both paths.
        for bad in ["10", "-1", "abc"] {
            assert!(gzip_compress(data, &level_args(bad)).is_err());
            assert!(make_gzip_compress(&level_args(bad)).is_err());
        }
    }

    #[test]
    fn zlib_level_supported_and_roundtrips() {
        let data = b"zlib level roundtrip payload, zlib level roundtrip payload!";
        let l0 = zlib_compress(data, &level_args("0")).unwrap();
        let l9 = zlib_compress(data, &level_args("9")).unwrap();
        assert_ne!(l0, l9);
        assert_eq!(zlib_decompress(&l0, &HashMap::new()).unwrap(), data);
        assert_eq!(zlib_decompress(&l9, &HashMap::new()).unwrap(), data);
        // Streaming matches memory at level 9.
        let mut s = make_zlib_compress(&level_args("9")).unwrap();
        let mut acc = Vec::new();
        for c in data.chunks(6) {
            acc.extend(s.write(c).unwrap());
        }
        acc.extend(s.finish().unwrap());
        assert_eq!(acc, l9);
        for bad in ["10", "x"] {
            assert!(zlib_compress(data, &level_args(bad)).is_err());
            assert!(make_zlib_compress(&level_args(bad)).is_err());
        }
    }

    #[test]
    fn deflate_level_supported_and_roundtrips() {
        let data: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
        let l1 = deflate_compress(&data, &level_args("1")).unwrap();
        let l9 = deflate_compress(&data, &level_args("9")).unwrap();
        assert_ne!(l1, l9);
        assert_eq!(deflate_decompress(&l1, &HashMap::new()).unwrap(), data);
        assert_eq!(deflate_decompress(&l9, &HashMap::new()).unwrap(), data);
        let mut s = make_deflate_compress(&level_args("1")).unwrap();
        let mut acc = Vec::new();
        for c in data.chunks(257) {
            acc.extend(s.write(c).unwrap());
        }
        acc.extend(s.finish().unwrap());
        assert_eq!(acc, l1);
        assert!(deflate_compress(&data, &level_args("11")).is_err());
        assert!(make_deflate_compress(&level_args("11")).is_err());
    }

    fn quality_args(q: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("quality".to_string(), q.to_string());
        m
    }

    #[test]
    fn brotli_quality_supported_and_roundtrips() {
        let data: Vec<u8> = b"brotli quality roundtrip payload ".repeat(64);
        let q0 = brotli_compress(&data, &quality_args("0")).unwrap();
        let q11 = brotli_compress(&data, &quality_args("11")).unwrap();
        assert_ne!(
            q0, q11,
            "different qualities must produce different brotli output"
        );
        assert_eq!(brotli_decompress(&q0, &HashMap::new()).unwrap(), data);
        assert_eq!(brotli_decompress(&q11, &HashMap::new()).unwrap(), data);
        // Default (no arg) equals quality 11 (the encoder default).
        assert_eq!(
            brotli_compress(&data, &HashMap::new()).unwrap(),
            brotli_compress(&data, &quality_args("11")).unwrap()
        );
        // Streaming factory carries quality through finish.
        let mut s = make_brotli_compress(&quality_args("0")).unwrap();
        let mut acc = Vec::new();
        for c in data.chunks(31) {
            acc.extend(s.write(c).unwrap());
        }
        acc.extend(s.finish().unwrap());
        assert_eq!(acc, q0);
        for bad in ["-1", "12", "high"] {
            assert!(brotli_compress(&data, &quality_args(bad)).is_err());
            assert!(make_brotli_compress(&quality_args(bad)).is_err());
        }
    }

    // --- LZMA / XZ -------------------------------------------------

    fn lzma_args(format: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("format".to_string(), format.to_string());
        m
    }

    #[test]
    fn lzma_xz_roundtrip_and_known_prefix() {
        let data: Vec<u8> = b"lzma xz roundtrip payload ".repeat(32);
        let enc = lzma_compress(&data, &HashMap::new()).unwrap();
        // XZ stream magic
        assert_eq!(&enc[..6], b"\xFD7zXZ\x00");
        assert_eq!(lzma_decompress(&enc, &HashMap::new()).unwrap(), data);
        // Explicit xz format behaves identically to the default.
        let enc_xz = lzma_compress(&data, &lzma_args("xz")).unwrap();
        assert_eq!(lzma_decompress(&enc_xz, &lzma_args("xz")).unwrap(), data);
        assert!(lzma_decompress(&enc, &lzma_args("xz")).unwrap() == data);
    }

    #[test]
    fn lzma_raw_roundtrip() {
        let data: Vec<u8> = b"raw lzma legacy container ".repeat(40);
        let enc = lzma_compress(&data, &lzma_args("lzma")).unwrap();
        // Legacy .lzma header magic: 0x5D then properties
        assert_eq!(enc[0], 0x5D);
        assert_eq!(lzma_decompress(&enc, &lzma_args("lzma")).unwrap(), data);
        // Cross-format must fail: xz container can't be read as raw lzma.
        let enc_xz = lzma_compress(&data, &HashMap::new()).unwrap();
        assert!(lzma_decompress(&enc_xz, &lzma_args("lzma")).is_err());
    }

    #[test]
    fn lzma_stream_matches_memory_and_rejects_bad_format() {
        let data: Vec<u8> = b"streaming lzma payload ".repeat(50);
        for fmt in ["xz", "lzma"] {
            let mem = lzma_compress(&data, &lzma_args(fmt)).unwrap();
            let mut s = make_lzma_compress(&lzma_args(fmt)).unwrap();
            let mut acc = Vec::new();
            for c in data.chunks(7) {
                acc.extend(s.write(c).unwrap());
            }
            acc.extend(s.finish().unwrap());
            assert_eq!(lzma_decompress(&acc, &lzma_args(fmt)).unwrap(), data);
            assert_eq!(
                lzma_decompress(&acc, &lzma_args(fmt)).unwrap(),
                lzma_decompress(&mem, &lzma_args(fmt)).unwrap()
            );
        }
        for bad in ["7z", "zip", ""] {
            assert!(lzma_compress(&data, &lzma_args(bad)).is_err());
            assert!(lzma_decompress(&data, &lzma_args(bad)).is_err());
            assert!(make_lzma_compress(&lzma_args(bad)).is_err());
        }
        assert!(lzma_decompress(b"garbage", &HashMap::new()).is_err());
    }

    // --- bzip2 (host-only) ----------------------------------------

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn bzip2_roundtrip_and_quality() {
        let data: Vec<u8> = b"bzip2 roundtrip payload ".repeat(64);
        let enc = bzip2_compress(&data, &HashMap::new()).unwrap();
        // bzip2 stream magic 'BZh'
        assert_eq!(&enc[..3], b"BZh");
        assert_eq!(bzip2_decompress(&enc, &HashMap::new()).unwrap(), data);
        let q1 = bzip2_compress(&data, &quality_args("1")).unwrap();
        let q9 = bzip2_compress(&data, &quality_args("9")).unwrap();
        assert_ne!(
            q1, q9,
            "different levels must produce different bzip2 output"
        );
        assert_eq!(&q1[..4], b"BZh1", "level 1 must use 100k block header");
        assert_eq!(&q9[..4], b"BZh9", "level 9 must use 900k block header");
        for c in [&q1, &q9] {
            assert_eq!(bzip2_decompress(c, &HashMap::new()).unwrap(), data);
        }
        for bad in ["0", "10", "high"] {
            assert!(bzip2_compress(&data, &quality_args(bad)).is_err());
            assert!(make_bzip2_compress(&quality_args(bad)).is_err());
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn bzip2_stream_matches_memory_and_rejects_garbage() {
        let data: Vec<u8> = b"bzip2 streaming payload ".repeat(48);
        let mem = bzip2_compress(&data, &HashMap::new()).unwrap();
        let mut s = make_bzip2_compress(&HashMap::new()).unwrap();
        let mut acc = Vec::new();
        for c in data.chunks(11) {
            acc.extend(s.write(c).unwrap());
        }
        acc.extend(s.finish().unwrap());
        assert_eq!(bzip2_decompress(&acc, &HashMap::new()).unwrap(), data);
        assert_eq!(
            bzip2_decompress(&acc, &HashMap::new()).unwrap(),
            bzip2_decompress(&mem, &HashMap::new()).unwrap()
        );
        assert!(bzip2_decompress(b"not bzip2", &HashMap::new()).is_err());
    }
}
