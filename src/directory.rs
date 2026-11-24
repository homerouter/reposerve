use actix_files::Directory;
use actix_web::{dev::ServiceResponse, HttpRequest, HttpResponse};
use chrono::{offset::Utc, DateTime};
use percent_encoding::{utf8_percent_encode, CONTROLS};
use size_format::SizeFormatterBinary;
use std::{fmt::Write, io, path::Path};
use v_htmlescape::escape_fmt as escape_html_entity;

struct DirEntry {
	name: String,
	url: String,
	dt: DateTime<Utc>,
	len: u64,
	is_dir: bool,
}

impl DirEntry {
	fn new(entry: std::fs::DirEntry, dir: &Directory, base: &Path) -> Option<Self> {
		if let Ok(metadata) = entry.metadata() {
			if let Ok(p) = entry.path().strip_prefix(&dir.path) {
				return Some(DirEntry {
					name: escape_html_entity(&entry.file_name().to_string_lossy()).to_string(),
					url: escape_html_entity(
						&utf8_percent_encode(&base.join(p).to_string_lossy(), CONTROLS).to_string(),
					)
					.to_string(),
					dt: metadata
						.modified()
						.unwrap_or(std::time::SystemTime::UNIX_EPOCH)
						.into(),
					len: metadata.len(),
					is_dir: metadata.is_dir(),
				});
			};
		}
		None
	}
}

pub fn directory_listing(dir: &Directory, req: &HttpRequest) -> Result<ServiceResponse, io::Error> {
	let index_of = format!("Index of {}", escape_html_entity(req.path()));
	let mut body = String::new();
	let base = Path::new(req.path());

	let mut entries: Vec<DirEntry> = dir
		.path
		.read_dir()?
		.filter(|e| dir.is_visible(e))
		.filter_map(Result::ok)
		.filter_map(|e| DirEntry::new(e, dir, base))
		.collect();

	entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name)));

	if dir.path != dir.base {
		let p = base.parent().unwrap_or_else(|| Path::new(""));
		let _ = write!(
			body,
			"<li><a href=\"{}\">../</a></li>",
			escape_html_entity(&utf8_percent_encode(&p.to_string_lossy(), CONTROLS).to_string())
		);
	}

	for entry in entries {
		if entry.is_dir {
			let _ = write!(
				body,
				"<li><span><a href=\"{}\">{}/</a></span></li>",
				entry.url, entry.name
			);
		} else {
			let _ = write!(
				body,
				"<li><span><a href=\"{}\">{}</a></span><span>{}</span><span>{}B</span></li>",
				entry.url,
				entry.name,
				entry.dt.format("%Y/%m/%d %T"),
				SizeFormatterBinary::new(entry.len)
			);
		}
	}

	let html = format!(
		"<html>\
         <head>
         <style>
         ul {{ list-style: none; }}
         li {{ display: flex; }}
         li:hover {{ background-color: lightgray; }}
         li>span {{ width: 33.333333%; }}
         </style>
         <title>{}</title></head>\
         <body><h1>{}</h1>\
         <hr>
         <ul>\
         {}\
         </ul><hr></body>\n</html>",
		index_of, index_of, body
	);
	Ok(ServiceResponse::new(
		req.clone(),
		HttpResponse::Ok()
			.content_type("text/html; charset=utf-8")
			.body(html),
	))
}

#[cfg(test)]
mod tests {
	use super::*;
	use actix_files::Files;
	use actix_web::{http::StatusCode, test, App};
	use std::fs;

	#[test]
	fn directory_listing_renders_visible_files_and_hides_dotfiles() {
		actix_web::rt::System::new().block_on(async {
			let dir = tempfile::tempdir().unwrap();
			let sub = dir.path().join("edge");
			fs::create_dir(&sub).unwrap();
			fs::write(sub.join("pkg-1.0.apk"), "abc").unwrap();
			fs::write(sub.join("a<b.apk"), "x").unwrap();
			fs::write(sub.join("q\"onmouseover=x.apk"), "x").unwrap();
			fs::create_dir(sub.join(".stage-1234")).unwrap();

			let app = test::init_service(
				App::new().service(
					Files::new("/", dir.path())
						.show_files_listing()
						.files_listing_renderer(directory_listing),
				),
			)
			.await;

			let req = test::TestRequest::get().uri("/edge/").to_request();
			let resp = test::call_service(&app, req).await;
			assert_eq!(resp.status(), StatusCode::OK);
			let html = String::from_utf8_lossy(&test::read_body(resp).await).into_owned();
			assert!(html.contains("pkg-1.0.apk"));
			assert!(html.contains("a&lt;b.apk"));
			assert!(!html.contains(".stage-1234"));
			assert!(!html.contains("q\"onmouseover"));
			assert!(!html.contains("a<b"));
		});
	}
}
