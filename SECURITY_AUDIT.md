# Reposerve Security & Architecture Audit Report

**Date**: November 24, 2026  
**Target Codebase**: `reposerve` v0.7.2 (commit `c38d0e0`)  
**Scope**: Multipart file upload, package staging, process lifecycle, directory rendering, and concurrency architecture.

---

## Executive Summary

The recent updates in v0.7.2 significantly improved system robustness by adding atomic packaging staging via hidden dot-directories, enforcing basic filename sanitization, adding process timeouts with `kill_on_drop`, and preventing subprocess error leaks.

However, a technical audit reveals several remaining vulnerabilities and architectural limitations across **Security**, **System Resilience**, **Client-Side Defense**, and **Concurrency Scalability**.

---

## Findings Matrix

| ID | Category | Severity | Title | Impact |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | Security / DoS | **High** | Unbounded Multipart File Upload Size | Disk space exhaustion, I/O starvation |
| **SEC-02** | Security / XSS | **Medium** | Unescaped Path in Directory Listing & Weak URL Encoding | Reflected XSS & HTML attribute injection |
| **RES-01** | Resilience | **Medium** | Orphaned `.stage-*` Staging Directories on Ungraceful Crash | Stale disk leaks over long-term operations |
| **PERF-01**| Concurrency | **Low / Opt** | Coarse-Grained Global Lock Serialization | Unnecessary lock contention across disparate repos |
| **PERF-02**| Performance | **Low / Opt** | Unbuffered Asynchronous Disk I/O | Elevated syscall overhead during uploads |

---

## Detailed Findings

### SEC-01: Unbounded Multipart File Upload Size (Denial of Service)

- **Location**: [`src/upload.rs:307-317`](file:///home/ezhang/reposerve/src/upload.rs#L307-L317)
- **Severity**: **High**
- **Description**:  
  While the server strictly enforces `MAX_FIELD_LEN = 256` for metadata fields (`version`, `repo`, `arch`), it enforces **no byte limit** on the streamed APK package payload:
  ```rust
  let mut f = tokio::fs::File::create(&filepath).await.map_err(|e| { ... })?;

  while let Some(chunk) = field.next().await {
      let data = chunk?;
      f.write_all(&data).await.map_err(|e| { ... })?;
  }
  ```
- **Exploitation / Failure Scenario**:  
  An authorized client (or any caller in `--dev` mode) can upload an arbitrarily large file (e.g. 50GB+) or stream infinite random bytes, exhausting server disk space and crashing host services (disk starvation DoS).
- **Remediation**:
  Define a configurable maximum package size (e.g., default `500 * 1024 * 1024` bytes / 500MB). Count bytes in the stream loop; if exceeded, immediately abort the stream, purge the temporary file, and return `413 Payload Too Large`.

---

### SEC-02: Reflected XSS and Attribute Injection in Directory Listings

- **Location**: [`src/directory.rs:38, 89-95`](file:///home/ezhang/reposerve/src/directory.rs#L38) & [`src/directory.rs:23, 65`](file:///home/ezhang/reposerve/src/directory.rs#L23)
- **Severity**: **Medium**
- **Description**:  
  1. **Unescaped Path**: The raw `req.path()` is formatted directly into the HTML title and heading:
     ```rust
     let index_of = format!("Index of {}", req.path());
     // ...
     let html = format!(
         "...<title>{}</title></head><body><h1>{}</h1>...",
         index_of, index_of, body
     );
     ```
     Actix-web URL-decodes the path before dispatching to the directory renderer. If a requested URI contains `<script>` or other HTML tags, it will be reflected raw in the response without entity escaping.
  2. **Insufficient URL Percent-Encoding**:
     ```rust
     url: utf8_percent_encode(&base.join(p).to_string_lossy(), CONTROLS).to_string(),
     ```
     The `CONTROLS` encode set only covers ASCII control characters (`0x00..=0x1F` and `0x7F`). It does not escape double quotes (`"`). On Linux filesystems where filenames may legitimately contain quotes, rendering `<a href="{}">` allows breaking out of the `href` HTML attribute.
- **Remediation**:
  - Run `escape_html_entity(&index_of)` before interpolating into the HTML template.
  - Use a stricter encode set (such as `NON_ALPHANUMERIC` or dedicated URI component sets) or pass attribute values through HTML escaping.

---

### RES-01: Orphaned `.stage-*` Staging Directories on Ungraceful Crash

- **Location**: [`src/upload.rs:167-175`](file:///home/ezhang/reposerve/src/upload.rs#L167-L175)
- **Severity**: **Medium**
- **Description**:  
  During upload, atomic staging uses `tempfile::Builder::new().prefix(".stage-").tempdir_in(&root_for_stage)`. Cleanup depends on Rust destructors (`drop((stage_dir, temp_dir))`).
- **Failure Scenario**:  
  If the process is ungracefully killed (e.g. Host OOM killer `SIGKILL`, abrupt container restart, power loss, or panic), temporary `.stage-xxxx` directories in the repository storage are never reclaimed. Although `.stage-*` files are hidden from the directory listing, they silently consume disk space over time.
- **Remediation**:
  Implement a startup garbage collection routine (or a light periodic sweep) that inspects the repository root and removes stale `.stage-*` directories older than a safety threshold (e.g., > 1 hour).

---

### PERF-01: Coarse-Grained Global Lock Serialization

- **Location**: [`src/main.rs:48`](file:///home/ezhang/reposerve/src/main.rs#L48), [`src/upload.rs:161`](file:///home/ezhang/reposerve/src/upload.rs#L161)
- **Severity**: **Low / Optimization**
- **Description**:  
  Uploads currently acquire a single global lock:
  ```rust
  let upload_lock = Data::new(UploadLock::new(()));
  // ponytail: global upload lock; shard per version/repo/arch if concurrent upload throughput matters
  ```
- **Impact**:  
  In CI/CD environments where concurrent pipelines publish packages for different Alpine versions and architectures simultaneously (e.g., `v3.18/main/x86_64` vs `edge/community/aarch64`), all uploads and indexing runs are serialized across the entire server.
- **Remediation**:
  Shard the lock by repository key `(version, repo, arch)` (using a keyed lock manager or striped locks), allowing independent repositories to build indexes concurrently while keeping individual repo targets serialized.

---

### PERF-02: Unbuffered Asynchronous Disk I/O

- **Location**: [`src/upload.rs:302-313`](file:///home/ezhang/reposerve/src/upload.rs#L302-L313)
- **Severity**: **Low / Optimization**
- **Description**:  
  Incoming multipart chunks (often 8KB - 64KB) are written directly to `tokio::fs::File::write_all` without buffering.
- **Remediation**:
  Wrap the output file in `tokio::io::BufWriter::new(f)` to batch writes and minimize async system call overhead.

---

## Action Plan & Recommendations

1. **Immediate (P0)**:
   - Enforce a 500MB upload size limit in `src/upload.rs` (return `413 Payload Too Large`).
   - Escape `index_of` in `src/directory.rs` to eliminate Reflected XSS.
2. **Hardening (P1)**:
   - Add startup cleanup for expired `.stage-*` directories in `Config::dir`.
   - Wrap chunk writes in `BufWriter`.
3. **Enhancement (P2)**:
   - Replace the global `UploadLock` with keyed `(version, repo, arch)` locking if concurrent pipeline throughput becomes a requirement.
