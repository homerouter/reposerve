use crate::config::Config;

use actix_multipart::Multipart;
use actix_web::{
	error::{ErrorBadRequest, ErrorInternalServerError},
	web::{self, BufMut, BytesMut},
	Error, HttpResponse,
};
use futures::{StreamExt, TryStreamExt};
use sanitize_filename::sanitize;
use std::{fs, path::Path, process::Stdio, time::Duration};
use tempfile::Builder;
use tokio::{io::AsyncWriteExt, process::Command};

pub(crate) type UploadLock = tokio::sync::Mutex<()>;

const MAX_FIELD_LEN: usize = 256;
const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(60);

fn sanitize_segment(raw: &str) -> Result<String, Error> {
	if raw.contains('/') || raw.contains('\\') {
		return Err(ErrorBadRequest("invalid repository parameter"));
	}
	let sane = sanitize(raw);
	if sane.is_empty() || sane.starts_with('.') || sane.starts_with('-') {
		return Err(ErrorBadRequest("invalid repository parameter"));
	}
	Ok(sane)
}

fn sanitize_apk_filename(raw: &str) -> Result<String, Error> {
	if raw.contains('/') || raw.contains('\\') {
		return Err(ErrorBadRequest("invalid apk filename"));
	}
	let sane = sanitize(raw);
	if sane.is_empty()
		|| sane.starts_with('.')
		|| sane.starts_with('-')
		|| !Path::new(&sane).extension().is_some_and(|ext| ext == "apk")
	{
		return Err(ErrorBadRequest("invalid apk filename"));
	}
	Ok(sane)
}

/// Represents an alpine repository
#[derive(Debug)]
struct ApkInfo {
	version: String,
	repo: String,
	arch: String,
}

impl Default for ApkInfo {
	fn default() -> Self {
		Self {
			version: "edge".to_owned(),
			repo: "main".to_owned(),
			arch: "x86_64".to_owned(),
		}
	}
}

impl ApkInfo {
	pub fn set(&mut self, f: &str, v: String) {
		match f {
			"version" => self.version = v,
			"repo" => self.repo = v,
			"arch" => self.arch = v,
			_ => (),
		}
	}
}

async fn run_command<I, S>(
	bin: &Path,
	cwd: &Path,
	args: I,
	timeout: Duration,
	label: &str,
	client_msg: &'static str,
) -> Result<(), Error>
where
	I: IntoIterator<Item = S>,
	S: AsRef<std::ffi::OsStr>,
{
	let mut cmd = Command::new(bin);
	cmd.current_dir(cwd)
		.args(args)
		.stdin(Stdio::null())
		.kill_on_drop(true);

	let output = match tokio::time::timeout(timeout, cmd.output()).await {
		Ok(Ok(output)) => output,
		Ok(Err(err)) => {
			log::error!("failed to execute {label} ({}): {err}", bin.display());
			return Err(ErrorInternalServerError(client_msg));
		}
		Err(_) => {
			log::error!("{label} ({}) timed out after {timeout:?}", bin.display());
			return Err(ErrorInternalServerError(client_msg));
		}
	};

	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		log::error!("{label} failed with status {:?}: {stderr}", output.status);
		return Err(ErrorInternalServerError(client_msg));
	}

	log::info!("{label}: {}", String::from_utf8_lossy(&output.stdout));
	Ok(())
}

/// upload new archives
pub(crate) async fn upload(
	payload: Multipart,
	config: web::Data<Config>,
	lock: web::Data<UploadLock>,
) -> Result<HttpResponse, Error> {
	upload_inner(
		payload,
		&config.dir,
		lock,
		Path::new("/sbin/apk"),
		Path::new("/usr/bin/abuild-sign"),
		SUBPROCESS_TIMEOUT,
	)
	.await
}

async fn upload_inner(
	mut payload: Multipart,
	repo_base: &Path,
	lock: web::Data<UploadLock>,
	apk_bin: &Path,
	sign_bin: &Path,
	timeout: Duration,
) -> Result<HttpResponse, Error> {
	let temp_dir = Builder::new().prefix("reposerve").tempdir().map_err(|e| {
		log::error!("failed to create upload temp dir: {e}");
		ErrorInternalServerError("upload staging failed")
	})?;

	let res = receive_multipart(&mut payload, temp_dir.path()).await;
	let (info, files) = match res {
		Ok(v) => v,
		Err(err) => {
			let _ = web::block(move || drop(temp_dir)).await;
			return Err(err);
		}
	};

	let sane_version = sanitize_segment(&info.version)?;
	let sane_repo = sanitize_segment(&info.repo)?;
	let sane_arch = sanitize_segment(&info.arch)?;
	let mut root = repo_base.join(sane_version);
	root.push(sane_repo);
	root.push(&sane_arch);

	let guard = lock.into_inner().lock_owned().await;

	let root_for_stage = root.clone();
	let files_for_stage = files.clone();
	let (temp_dir, stage_dir, apk_files) = web::block(move || -> std::io::Result<_> {
		fs::create_dir_all(&root_for_stage)?;
		let stage_dir = Builder::new()
			.prefix(".stage-")
			.tempdir_in(&root_for_stage)?;

		for file in &files_for_stage {
			let src = temp_dir.path().join(file);
			let dst = stage_dir.path().join(file);
			fs::rename(&src, &dst).or_else(|_| fs::copy(&src, &dst).map(|_| ()))?;
		}

		for entry in fs::read_dir(&root_for_stage)? {
			let entry = entry?;
			let path = entry.path();
			let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
				continue;
			};
			if name.starts_with('.') || Path::new(name).extension() != Some("apk".as_ref()) {
				continue;
			}
			if !fs::metadata(&path)?.is_file() {
				continue;
			}
			let staged = stage_dir.path().join(name);
			if !staged.exists() {
				fs::hard_link(&path, &staged).or_else(|_| fs::copy(&path, &staged).map(|_| ()))?;
			}
		}

		let mut apk_files = Vec::new();
		for entry in fs::read_dir(stage_dir.path())? {
			let entry = entry?;
			let path = entry.path();
			if path.extension() == Some("apk".as_ref()) && fs::metadata(&path)?.is_file() {
				let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
					std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid apk filename")
				})?;
				apk_files.push(name.to_owned());
			}
		}
		apk_files.sort();
		Ok((temp_dir, stage_dir, apk_files))
	})
	.await
	.map_err(|e| {
		log::error!("staging task error: {e}");
		ErrorInternalServerError("upload staging failed")
	})?
	.map_err(|e| {
		log::error!("staging io error: {e}");
		ErrorInternalServerError("upload staging failed")
	})?;

	let mut apk_args = vec![
		"index".to_owned(),
		"-o".to_owned(),
		"APKINDEX.tar.gz".to_owned(),
		"--rewrite-arch".to_owned(),
		sane_arch,
		"--".to_owned(),
	];
	apk_args.extend(apk_files);

	if let Err(err) = run_command(
		apk_bin,
		stage_dir.path(),
		&apk_args,
		timeout,
		"apk",
		"package indexing failed",
	)
	.await
	{
		let _ = web::block(move || drop((stage_dir, temp_dir))).await;
		return Err(err);
	}

	if let Err(err) = run_command(
		sign_bin,
		stage_dir.path(),
		["APKINDEX.tar.gz"],
		timeout,
		"abuild-sign",
		"package signing failed",
	)
	.await
	{
		let _ = web::block(move || drop((stage_dir, temp_dir))).await;
		return Err(err);
	}

	web::block(move || -> std::io::Result<()> {
		for file in &files {
			fs::rename(stage_dir.path().join(file), root.join(file))?;
		}
		fs::rename(
			stage_dir.path().join("APKINDEX.tar.gz"),
			root.join("APKINDEX.tar.gz"),
		)?;
		drop((stage_dir, temp_dir, guard));
		Ok(())
	})
	.await
	.map_err(|e| {
		log::error!("commit task error: {e}");
		ErrorInternalServerError("failed to publish repository update")
	})?
	.map_err(|e| {
		log::error!("commit io error: {e}");
		ErrorInternalServerError("failed to publish repository update")
	})?;

	Ok(HttpResponse::Ok().finish())
}

async fn receive_multipart(
	payload: &mut Multipart,
	temp_path: &Path,
) -> Result<(ApkInfo, Vec<String>), Error> {
	let mut info = ApkInfo::default();
	let mut files = Vec::new();
	while let Some(mut field) = payload.try_next().await? {
		let cd = field.content_disposition();
		match cd.as_ref().and_then(|cd| cd.get_name()) {
			Some("file") => {
				let filename = cd
					.as_ref()
					.and_then(|cd| cd.get_filename())
					.ok_or_else(|| ErrorBadRequest("missing apk filename"))?;
				let sane_file = sanitize_apk_filename(filename)?;
				let filepath = temp_path.join(&sane_file);
				log::info!("saving {}", filepath.display());
				if !files.contains(&sane_file) {
					files.push(sane_file);
				}

				let mut f = tokio::fs::File::create(&filepath).await.map_err(|e| {
					log::error!("failed to create temp upload file: {e}");
					ErrorInternalServerError("failed to save uploaded file")
				})?;

				while let Some(chunk) = field.next().await {
					let data = chunk?;
					f.write_all(&data).await.map_err(|e| {
						log::error!("failed to write temp upload chunk: {e}");
						ErrorInternalServerError("failed to save uploaded file")
					})?;
				}
				f.flush().await.map_err(|e| {
					log::error!("failed to flush temp upload file: {e}");
					ErrorInternalServerError("failed to save uploaded file")
				})?;
			}
			Some(f) if f == "version" || f == "repo" || f == "arch" => {
				let mut data = BytesMut::with_capacity(32);
				let field_name = f.to_owned();
				while let Some(chunk) = field.next().await {
					let chunk = chunk?;
					if data.len() + chunk.len() > MAX_FIELD_LEN {
						return Err(ErrorBadRequest("repository parameter too large"));
					}
					data.put(chunk);
				}
				let val = std::str::from_utf8(&data)
					.map_err(|_| ErrorBadRequest("invalid utf-8 in repository parameter"))?;
				info.set(&field_name, val.to_owned());
			}
			_ => (),
		}
	}

	if files.is_empty() {
		return Err(ErrorBadRequest("no apk file uploaded"));
	}

	Ok((info, files))
}

#[cfg(test)]
mod tests {
	use super::*;
	use actix_web::{http::StatusCode, test, App};

	fn test_config(dir: &std::path::Path) -> web::Data<Config> {
		web::Data::new(Config {
			dir: dir.to_path_buf(),
			tls: None,
			webhooks: None,
			jwt: None,
		})
	}

	fn run_async<F: std::future::Future<Output = ()>>(f: F) {
		actix_web::rt::System::new().block_on(f);
	}

	#[test]
	fn rejects_non_multipart_post() {
		run_async(async {
			let repo_dir = tempfile::tempdir().unwrap();
			let app = test::init_service(
				App::new()
					.app_data(test_config(repo_dir.path()))
					.app_data(web::Data::new(UploadLock::new(())))
					.route("/upload", web::post().to(upload)),
			)
			.await;

			let req = test::TestRequest::post()
				.uri("/upload")
				.insert_header(("Content-Type", "text/plain"))
				.set_payload("not multipart")
				.to_request();
			let resp = test::call_service(&app, req).await;

			assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
			assert!(!repo_dir.path().join("edge").exists());
		});
	}

	#[test]
	fn rejects_truncated_multipart_stream_without_touching_repo() {
		run_async(async {
			let repo_dir = tempfile::tempdir().unwrap();
			let app = test::init_service(
				App::new()
					.app_data(test_config(repo_dir.path()))
					.app_data(web::Data::new(UploadLock::new(())))
					.route("/upload", web::post().to(upload)),
			)
			.await;

			// Valid first file part, then truncated in next part header where payload.try_next() errors
			let body = concat!(
				"--BOUND\r\n",
				"Content-Disposition: form-data; name=\"file\"; filename=\"pkg-1.0-r0.apk\"\r\n\r\n",
				"fake-apk-bytes\r\n",
				"--BOUND\r\n",
				"Content-Disposition: form-data; name=\"ver"
			);
			let req = test::TestRequest::post()
				.uri("/upload")
				.insert_header(("Content-Type", "multipart/form-data; boundary=BOUND"))
				.set_payload(body)
				.to_request();
			let resp = test::call_service(&app, req).await;

			assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
			assert!(!repo_dir.path().join("edge").exists());
		});
	}

	#[test]
	fn rejects_multipart_without_apk_files() {
		run_async(async {
			let repo_dir = tempfile::tempdir().unwrap();
			let app = test::init_service(
				App::new()
					.app_data(test_config(repo_dir.path()))
					.app_data(web::Data::new(UploadLock::new(())))
					.route("/upload", web::post().to(upload)),
			)
			.await;

			let body = concat!(
				"--BOUND\r\n",
				"Content-Disposition: form-data; name=\"version\"\r\n\r\n",
				"v3.20\r\n",
				"--BOUND--\r\n"
			);
			let req = test::TestRequest::post()
				.uri("/upload")
				.insert_header(("Content-Type", "multipart/form-data; boundary=BOUND"))
				.set_payload(body)
				.to_request();
			let resp = test::call_service(&app, req).await;

			assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
			assert!(!repo_dir.path().join("v3.20").exists());
		});
	}

	#[test]
	fn rejects_invalid_filenames_and_repo_segments() {
		run_async(async {
			let repo_dir = tempfile::tempdir().unwrap();
			let app = test::init_service(
				App::new()
					.app_data(test_config(repo_dir.path()))
					.app_data(web::Data::new(UploadLock::new(())))
					.route("/upload", web::post().to(upload)),
			)
			.await;

			let bad_cases = [
				("..", "edge", "main", "x86_64"),
				("../evil.apk", "edge", "main", "x86_64"),
				(".hidden.apk", "edge", "main", "x86_64"),
				("-flag.apk", "edge", "main", "x86_64"),
				("APKINDEX.tar.gz", "edge", "main", "x86_64"),
				("pkg-1.0-r0.apk", "..", "main", "x86_64"),
				("pkg-1.0-r0.apk", "edge", ".", "x86_64"),
				("pkg-1.0-r0.apk", "edge", "main", "-x86_64"),
				("pkg-1.0-r0.apk", "edge/sub", "main", "x86_64"),
			];

			for (filename, version, repo, arch) in bad_cases {
				let body = format!(
					"--BOUND\r\n\
					 Content-Disposition: form-data; name=\"version\"\r\n\r\n{version}\r\n\
					 --BOUND\r\n\
					 Content-Disposition: form-data; name=\"repo\"\r\n\r\n{repo}\r\n\
					 --BOUND\r\n\
					 Content-Disposition: form-data; name=\"arch\"\r\n\r\n{arch}\r\n\
					 --BOUND\r\n\
					 Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n\r\n\
					 data\r\n\
					 --BOUND--\r\n"
				);
				let req = test::TestRequest::post()
					.uri("/upload")
					.insert_header(("Content-Type", "multipart/form-data; boundary=BOUND"))
					.set_payload(body)
					.to_request();
				let resp = test::call_service(&app, req).await;
				assert_eq!(
					resp.status(),
					StatusCode::BAD_REQUEST,
					"expected 400 for case ({filename}, {version}, {repo}, {arch})"
				);
			}
		});
	}

	#[test]
	fn rejects_oversized_metadata_field() {
		run_async(async {
			let repo_dir = tempfile::tempdir().unwrap();
			let app = test::init_service(
				App::new()
					.app_data(test_config(repo_dir.path()))
					.app_data(web::Data::new(UploadLock::new(())))
					.route("/upload", web::post().to(upload)),
			)
			.await;

			let huge_version = "v".repeat(512);
			let body = format!(
				"--BOUND\r\n\
				 Content-Disposition: form-data; name=\"version\"\r\n\r\n{huge_version}\r\n\
				 --BOUND\r\n\
				 Content-Disposition: form-data; name=\"file\"; filename=\"pkg-1.0-r0.apk\"\r\n\r\n\
				 data\r\n\
				 --BOUND--\r\n"
			);
			let req = test::TestRequest::post()
				.uri("/upload")
				.insert_header(("Content-Type", "multipart/form-data; boundary=BOUND"))
				.set_payload(body)
				.to_request();
			let resp = test::call_service(&app, req).await;

			assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
		});
	}

	fn write_script(dir: &Path, name: &str, content: &str) -> std::path::PathBuf {
		use std::os::unix::fs::PermissionsExt;
		let path = dir.join(name);
		fs::write(&path, content).unwrap();
		fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
		path
	}

	fn multipart_apk_body(
		version: &str,
		repo: &str,
		arch: &str,
		filename: &str,
		content: &str,
	) -> String {
		format!(
			"--BOUND\r\n\
			 Content-Disposition: form-data; name=\"version\"\r\n\r\n{version}\r\n\
			 --BOUND\r\n\
			 Content-Disposition: form-data; name=\"repo\"\r\n\r\n{repo}\r\n\
			 --BOUND\r\n\
			 Content-Disposition: form-data; name=\"arch\"\r\n\r\n{arch}\r\n\
			 --BOUND\r\n\
			 Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n\r\n\
			 {content}\r\n\
			 --BOUND--\r\n"
		)
	}

	#[test]
	fn corrupt_apk_does_not_wedge_repo_or_leak_stderr() {
		run_async(async {
			let repo_dir = tempfile::tempdir().unwrap();
			let bin_dir = tempfile::tempdir().unwrap();
			let apk_bin = write_script(
				bin_dir.path(),
				"fake-apk.sh",
				concat!(
					"#!/bin/sh\n",
					"# Expect: index -o APKINDEX.tar.gz --rewrite-arch <arch> -- <files...>\n",
					"if [ \"$1\" != \"index\" ] || [ \"$2\" != \"-o\" ] || [ \"$4\" != \"--rewrite-arch\" ] || [ \"$6\" != \"--\" ]; then\n",
					"  echo \"BAD_ARGS:$*\" >&2; exit 2\n",
					"fi\n",
					"OUT=\"$3\"; ARCH=\"$5\"; shift 6\n",
					"for f in \"$@\"; do\n",
					"  if [ \"$(cat \"$f\")\" = \"CORRUPT\" ]; then\n",
					"    echo \"INTERNAL_SECRET_APK_STDERR\" >&2\n",
					"    exit 1\n",
					"  fi\n",
					"done\n",
					"printf 'UNSIGNED:%s:%s' \"$ARCH\" \"$*\" > \"$OUT\"\n",
				),
			);
			let sign_bin = write_script(
				bin_dir.path(),
				"fake-sign.sh",
				concat!(
					"#!/bin/sh\n",
					"CONTENT=$(cat \"$1\")\n",
					"printf 'SIGNED:%s' \"$CONTENT\" > \"$1\"\n",
				),
			);

			let repo_path = repo_dir.path().to_path_buf();
			let lock = web::Data::new(tokio::sync::Mutex::new(()));
			let app = test::init_service(App::new().app_data(lock.clone()).route(
				"/upload",
				web::post().to({
					let repo_path = repo_path.clone();
					let apk_bin = apk_bin.clone();
					let sign_bin = sign_bin.clone();
					move |payload: Multipart, lock: web::Data<tokio::sync::Mutex<()>>| {
						let repo_path = repo_path.clone();
						let apk_bin = apk_bin.clone();
						let sign_bin = sign_bin.clone();
						async move {
							upload_inner(
								payload,
								&repo_path,
								lock,
								&apk_bin,
								&sign_bin,
								std::time::Duration::from_secs(5),
							)
							.await
						}
					}
				}),
			))
			.await;

			// 1. Valid initial upload
			let req1 = test::TestRequest::post()
				.uri("/upload")
				.insert_header(("Content-Type", "multipart/form-data; boundary=BOUND"))
				.set_payload(multipart_apk_body(
					"v3.20",
					"main",
					"aarch64",
					"a-1.0.apk",
					"VALID1",
				))
				.to_request();
			let resp1 = test::call_service(&app, req1).await;
			assert_eq!(resp1.status(), StatusCode::OK);
			let root = repo_dir.path().join("v3.20/main/aarch64");
			assert_eq!(
				fs::read_to_string(root.join("APKINDEX.tar.gz")).unwrap(),
				"SIGNED:UNSIGNED:aarch64:a-1.0.apk"
			);

			// 2. Corrupt package upload must fail with 500, NOT leak stderr/paths, NOT leave bad.apk in root
			let req2 = test::TestRequest::post()
				.uri("/upload")
				.insert_header(("Content-Type", "multipart/form-data; boundary=BOUND"))
				.set_payload(multipart_apk_body(
					"v3.20",
					"main",
					"aarch64",
					"bad-1.0.apk",
					"CORRUPT",
				))
				.to_request();
			let resp2 = test::call_service(&app, req2).await;
			assert_eq!(resp2.status(), StatusCode::INTERNAL_SERVER_ERROR);
			let err_body = String::from_utf8_lossy(&test::read_body(resp2).await).into_owned();
			assert!(
				!err_body.contains("INTERNAL_SECRET_APK_STDERR"),
				"leaked stderr: {err_body}"
			);
			assert!(
				!root.join("bad-1.0.apk").exists(),
				"corrupt apk poisoned live repo"
			);
			assert_eq!(
				fs::read_to_string(root.join("APKINDEX.tar.gz")).unwrap(),
				"SIGNED:UNSIGNED:aarch64:a-1.0.apk"
			);

			// 3. Subsequent valid upload must still succeed (repo not wedged!)
			let req3 = test::TestRequest::post()
				.uri("/upload")
				.insert_header(("Content-Type", "multipart/form-data; boundary=BOUND"))
				.set_payload(multipart_apk_body(
					"v3.20",
					"main",
					"aarch64",
					"b-1.0.apk",
					"VALID2",
				))
				.to_request();
			let resp3 = test::call_service(&app, req3).await;
			assert_eq!(resp3.status(), StatusCode::OK);
			assert_eq!(
				fs::read_to_string(root.join("APKINDEX.tar.gz")).unwrap(),
				"SIGNED:UNSIGNED:aarch64:a-1.0.apk b-1.0.apk"
			);
		});
	}

	#[test]
	fn signing_failure_preserves_signed_index_and_existing_package() {
		run_async(async {
			let repo_dir = tempfile::tempdir().unwrap();
			let bin_dir = tempfile::tempdir().unwrap();
			let fail_flag = bin_dir.path().join("fail_sign");
			let apk_bin = write_script(
				bin_dir.path(),
				"fake-apk.sh",
				concat!(
					"#!/bin/sh\n",
					"OUT=\"$3\"; ARCH=\"$5\"; shift 6\n",
					"printf 'UNSIGNED:%s:%s' \"$ARCH\" \"$*\" > \"$OUT\"\n",
				),
			);
			let sign_bin = write_script(
				bin_dir.path(),
				"fake-sign.sh",
				&format!(
					"#!/bin/sh\n\
					 if [ -f \"{}\" ]; then echo 'SECRET_SIGN_ERR' >&2; exit 1; fi\n\
					 CONTENT=$(cat \"$1\")\n\
					 printf 'SIGNED:%s' \"$CONTENT\" > \"$1\"\n",
					fail_flag.display()
				),
			);

			let repo_path = repo_dir.path().to_path_buf();
			let lock = web::Data::new(tokio::sync::Mutex::new(()));
			let app = test::init_service(App::new().app_data(lock.clone()).route(
				"/upload",
				web::post().to({
					let repo_path = repo_path.clone();
					let apk_bin = apk_bin.clone();
					let sign_bin = sign_bin.clone();
					move |payload: Multipart, lock: web::Data<tokio::sync::Mutex<()>>| {
						let repo_path = repo_path.clone();
						let apk_bin = apk_bin.clone();
						let sign_bin = sign_bin.clone();
						async move {
							upload_inner(
								payload,
								&repo_path,
								lock,
								&apk_bin,
								&sign_bin,
								std::time::Duration::from_secs(5),
							)
							.await
						}
					}
				}),
			))
			.await;

			// 1. Seed valid package v1
			let req1 = test::TestRequest::post()
				.uri("/upload")
				.insert_header(("Content-Type", "multipart/form-data; boundary=BOUND"))
				.set_payload(multipart_apk_body(
					"edge",
					"main",
					"x86_64",
					"pkg-1.0.apk",
					"V1",
				))
				.to_request();
			assert_eq!(
				test::call_service(&app, req1).await.status(),
				StatusCode::OK
			);

			// 2. Trigger signing failure while overwriting pkg-1.0.apk with V2
			fs::write(&fail_flag, "1").unwrap();
			let req2 = test::TestRequest::post()
				.uri("/upload")
				.insert_header(("Content-Type", "multipart/form-data; boundary=BOUND"))
				.set_payload(multipart_apk_body(
					"edge",
					"main",
					"x86_64",
					"pkg-1.0.apk",
					"V2",
				))
				.to_request();
			let resp2 = test::call_service(&app, req2).await;
			assert_eq!(resp2.status(), StatusCode::INTERNAL_SERVER_ERROR);
			let err_body = String::from_utf8_lossy(&test::read_body(resp2).await).into_owned();
			assert!(!err_body.contains("SECRET_SIGN_ERR"));

			let root = repo_dir.path().join("edge/main/x86_64");
			assert_eq!(
				fs::read_to_string(root.join("APKINDEX.tar.gz")).unwrap(),
				"SIGNED:UNSIGNED:x86_64:pkg-1.0.apk",
				"unsigned APKINDEX.tar.gz leaked into live repo!"
			);
			assert_eq!(
				fs::read_to_string(root.join("pkg-1.0.apk")).unwrap(),
				"V1",
				"existing package was overwritten despite failed signing!"
			);
		});
	}

	#[test]
	fn upload_times_out_hung_subprocess() {
		run_async(async {
			let repo_dir = tempfile::tempdir().unwrap();
			let bin_dir = tempfile::tempdir().unwrap();
			let apk_bin = write_script(bin_dir.path(), "slow-apk.sh", "#!/bin/sh\nexec sleep 30\n");
			let sign_bin = write_script(bin_dir.path(), "sign.sh", "#!/bin/sh\nexit 0\n");

			let repo_path = repo_dir.path().to_path_buf();
			let lock = web::Data::new(tokio::sync::Mutex::new(()));
			let app = test::init_service(App::new().app_data(lock.clone()).route(
				"/upload",
				web::post().to(
					move |payload: Multipart, lock: web::Data<tokio::sync::Mutex<()>>| {
						let repo_path = repo_path.clone();
						let apk_bin = apk_bin.clone();
						let sign_bin = sign_bin.clone();
						async move {
							upload_inner(
								payload,
								&repo_path,
								lock,
								&apk_bin,
								&sign_bin,
								std::time::Duration::from_millis(100),
							)
							.await
						}
					},
				),
			))
			.await;

			let start = std::time::Instant::now();
			let req = test::TestRequest::post()
				.uri("/upload")
				.insert_header(("Content-Type", "multipart/form-data; boundary=BOUND"))
				.set_payload(multipart_apk_body(
					"edge",
					"main",
					"x86_64",
					"pkg-1.0.apk",
					"DATA",
				))
				.to_request();
			let resp = test::call_service(&app, req).await;
			assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
			assert!(
				start.elapsed() < std::time::Duration::from_secs(10),
				"subprocess timeout did not abort promptly"
			);
			assert!(!repo_dir
				.path()
				.join("edge/main/x86_64/pkg-1.0.apk")
				.exists());
		});
	}

	#[test]
	fn concurrent_uploads_serialize_and_preserve_all_packages() {
		run_async(async {
			let repo_dir = tempfile::tempdir().unwrap();
			let bin_dir = tempfile::tempdir().unwrap();
			let apk_bin = write_script(
				bin_dir.path(),
				"fake-apk.sh",
				concat!(
					"#!/bin/sh\n",
					"OUT=\"$3\"; ARCH=\"$5\"; shift 6\n",
					"printf 'UNSIGNED:%s:%s' \"$ARCH\" \"$*\" > \"$OUT\"\n",
				),
			);
			let sign_bin = write_script(
				bin_dir.path(),
				"fake-sign.sh",
				concat!(
					"#!/bin/sh\n",
					"CONTENT=$(cat \"$1\")\n",
					"case \"$CONTENT\" in *\" \"*) ;; *) sleep 0.08 ;; esac\n",
					"printf 'SIGNED:%s' \"$CONTENT\" > \"$1\"\n",
				),
			);

			let repo_path = repo_dir.path().to_path_buf();
			let lock = web::Data::new(tokio::sync::Mutex::new(()));
			let app = test::init_service(App::new().app_data(lock.clone()).route(
				"/upload",
				web::post().to(
					move |payload: Multipart, lock: web::Data<tokio::sync::Mutex<()>>| {
						let repo_path = repo_path.clone();
						let apk_bin = apk_bin.clone();
						let sign_bin = sign_bin.clone();
						async move {
							upload_inner(
								payload,
								&repo_path,
								lock,
								&apk_bin,
								&sign_bin,
								std::time::Duration::from_secs(5),
							)
							.await
						}
					},
				),
			))
			.await;

			let req_a = test::TestRequest::post()
				.uri("/upload")
				.insert_header(("Content-Type", "multipart/form-data; boundary=BOUND"))
				.set_payload(multipart_apk_body(
					"edge",
					"main",
					"x86_64",
					"a-1.0.apk",
					"A",
				))
				.to_request();
			let req_b = test::TestRequest::post()
				.uri("/upload")
				.insert_header(("Content-Type", "multipart/form-data; boundary=BOUND"))
				.set_payload(multipart_apk_body(
					"edge",
					"main",
					"x86_64",
					"b-1.0.apk",
					"B",
				))
				.to_request();

			let (resp_a, resp_b) = futures::future::join(test::call_service(&app, req_a), async {
				tokio::time::sleep(std::time::Duration::from_millis(15)).await;
				test::call_service(&app, req_b).await
			})
			.await;
			assert_eq!(resp_a.status(), StatusCode::OK);
			assert_eq!(resp_b.status(), StatusCode::OK);

			let root = repo_dir.path().join("edge/main/x86_64");
			assert_eq!(
				fs::read_to_string(root.join("APKINDEX.tar.gz")).unwrap(),
				"SIGNED:UNSIGNED:x86_64:a-1.0.apk b-1.0.apk"
			);
			// Verify no leftover .stage-* directories remain
			for entry in fs::read_dir(&root).unwrap() {
				let name = entry.unwrap().file_name().into_string().unwrap();
				assert!(!name.starts_with(".stage-"), "leftover stage dir: {name}");
			}
		});
	}
}
