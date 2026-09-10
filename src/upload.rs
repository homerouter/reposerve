use crate::config::Config;

use actix_multipart::Multipart;
use actix_web::{
	web::{self, BufMut, BytesMut},
	Error, HttpResponse,
};
use futures::{StreamExt, TryStreamExt};
use sanitize_filename::sanitize;
use std::{fs, process::Command};
use tempfile::Builder;
use tokio::io::AsyncWriteExt;

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

/// upload new archives
pub(crate) async fn upload(
	mut payload: Multipart,
	config: web::Data<Config>,
) -> Result<HttpResponse, Error> {
	let temp_dir = Builder::new().prefix("reposerve").tempdir()?;

	// iterate over multipart stream
	let mut info = ApkInfo::default();
	let mut files = Vec::new();
	while let Ok(Some(mut field)) = payload.try_next().await {
		let cd = field.content_disposition();
		// handle named fields
		match cd.as_ref().and_then(|cd| cd.get_name()) {
			// save file to tmp dir
			Some("file") => {
				if let Some(filename) = cd.as_ref().and_then(|cd| cd.get_filename()) {
					let sane_file = sanitize(filename);
					let filepath = temp_dir.path().join(&sane_file);
					log::info!("saving {}", filepath.display());
					files.push(sane_file);

					let mut f = tokio::fs::File::create(&filepath).await?;

					// File data is a stream of *Bytes*
					while let Some(chunk) = field.next().await {
						let data = chunk?;
						f.write_all(&data).await?;
					}
					f.flush().await?;
				}
			}
			// get repo parameters (for moving the files to the right place)
			Some(f) if f == "version" || f == "repo" || f == "arch" => {
				let mut data = BytesMut::with_capacity(32);
				// copy the field name before advancing to the next one
				let field_name = f.to_owned();
				// Field value is a stream of *Bytes*
				while let Some(chunk) = field.next().await {
					data.put(chunk?);
				}
				info.set(&field_name, String::from_utf8_lossy(&data).into_owned());
			}
			// ignore the rest
			_ => (),
		}
	}

	// create dest dir if necessary
	let mut root = config.dir.join(sanitize(&info.version));
	root.push(sanitize(&info.repo));
	root.push(sanitize(&info.arch));

	let temp_dir_path = temp_dir.path().to_path_buf();
	let info_arch = info.arch.clone();
	web::block(move || -> std::io::Result<()> {
		fs::create_dir_all(&root)?;

		// move files to correct destinations when we have all the info
		for file in files {
			let src = temp_dir_path.join(&file);
			let dst = root.join(&file);
			fs::copy(&src, &dst)?;
		}

		// call apk to index all .apk files in root
		let mut apk_args: Vec<String> = [
			"index",
			"-o",
			"APKINDEX.tar.gz",
			"--rewrite-arch",
			&info_arch,
		]
		.iter()
		.map(|s| s.to_string())
		.collect();
		for entry in fs::read_dir(&root)? {
			let entry = entry?;
			let path = entry.path();
			if let Some(ext) = path.extension() {
				let metadata = fs::metadata(&path)?;
				if metadata.is_file() && ext == "apk" {
					let file_name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
						std::io::Error::new(
							std::io::ErrorKind::InvalidData,
							format!("non-utf8 or invalid file name for apk: {:?}", path),
						)
					})?;
					apk_args.push(file_name.to_owned());
				}
			}
		}
		let output = Command::new("/sbin/apk")
			.current_dir(&root)
			.args(&apk_args)
			.output()?;
		if !output.status.success() {
			let stderr = String::from_utf8_lossy(&output.stderr);
			log::error!("apk failed with status {:?}: {}", output.status, stderr);
			return Err(std::io::Error::new(
				std::io::ErrorKind::Other,
				format!(
					"apk index failed with status {:?}: {}",
					output.status, stderr
				),
			));
		}
		log::info!("apk: {}", String::from_utf8_lossy(&output.stdout));

		// call abuild-sign to sign generated index
		let output = Command::new("/usr/bin/abuild-sign")
			.current_dir(&root)
			.args(["APKINDEX.tar.gz"])
			.output()?;
		if !output.status.success() {
			let stderr = String::from_utf8_lossy(&output.stderr);
			log::error!(
				"abuild-sign failed with status {:?}: {}",
				output.status,
				stderr
			);
			return Err(std::io::Error::new(
				std::io::ErrorKind::Other,
				format!(
					"abuild-sign failed with status {:?}: {}",
					output.status, stderr
				),
			));
		}
		log::info!("abuild-sign: {}", String::from_utf8_lossy(&output.stdout));
		Ok(())
	})
	.await
	.map_err(actix_web::error::ErrorInternalServerError)??;

	Ok(HttpResponse::Ok().finish())
}
