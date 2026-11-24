use crate::config::Config;

use actix_web::{web, HttpResponse};
use std::{process::Stdio, time::Duration};
use tokio::process::Command;

const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) async fn webhook(webhook: web::Path<String>, config: web::Data<Config>) -> HttpResponse {
	webhook_inner(webhook.into_inner(), &config, WEBHOOK_TIMEOUT).await
}

async fn webhook_inner(webhook: String, config: &Config, timeout: Duration) -> HttpResponse {
	let Some(ref webhooks) = config.webhooks else {
		log::warn!("received webhook request but webhooks are not configured");
		return HttpResponse::NotFound().body("webhooks not configured");
	};

	let Some(script) = webhooks.get(webhook.as_str()) else {
		return HttpResponse::NotFound().body("webhook not found");
	};

	let mut cmd = Command::new(script);
	cmd.stdin(Stdio::null()).kill_on_drop(true);

	match tokio::time::timeout(timeout, cmd.output()).await {
		Ok(Ok(output)) => {
			if output.status.success() {
				HttpResponse::Ok().body(format!(
					"webhook {} executed with success: {}",
					webhook,
					String::from_utf8_lossy(&output.stdout)
				))
			} else {
				log::error!(
					"webhook {} ({}) exited with non-zero status {:?}: {}",
					webhook,
					script,
					output.status.code(),
					String::from_utf8_lossy(&output.stderr)
				);
				HttpResponse::InternalServerError().body("webhook execution failed")
			}
		}
		Ok(Err(error)) => {
			log::error!(
				"failed to execute webhook {} ({}): {}",
				webhook,
				script,
				error
			);
			HttpResponse::InternalServerError().body("webhook execution failed")
		}
		Err(_) => {
			log::error!(
				"webhook {} ({}) timed out after {:?}",
				webhook,
				script,
				timeout
			);
			HttpResponse::InternalServerError().body("webhook execution timed out")
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use actix_web::{http::StatusCode, test, App};
	use std::{collections::HashMap, fs, path::Path, time::Duration};

	fn run_async<F: std::future::Future<Output = ()>>(f: F) {
		actix_web::rt::System::new().block_on(f);
	}

	fn write_script(dir: &Path, name: &str, content: &str) -> String {
		use std::os::unix::fs::PermissionsExt;
		let path = dir.join(name);
		fs::write(&path, content).unwrap();
		fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
		path.to_str().unwrap().to_owned()
	}

	#[test]
	fn returns_404_when_unconfigured_or_unknown() {
		run_async(async {
			let dir = tempfile::tempdir().unwrap();
			let app_none = test::init_service(
				App::new()
					.app_data(web::Data::new(Config {
						dir: dir.path().to_path_buf(),
						tls: None,
						webhooks: None,
						jwt: None,
					}))
					.route("/webhook/{webhook}", web::post().to(webhook)),
			)
			.await;
			let req = test::TestRequest::post().uri("/webhook/sign").to_request();
			assert_eq!(
				test::call_service(&app_none, req).await.status(),
				StatusCode::NOT_FOUND
			);

			let mut hooks = HashMap::new();
			hooks.insert("sign".to_owned(), "/bin/true".to_owned());
			let app_some = test::init_service(
				App::new()
					.app_data(web::Data::new(Config {
						dir: dir.path().to_path_buf(),
						tls: None,
						webhooks: Some(hooks),
						jwt: None,
					}))
					.route("/webhook/{webhook}", web::post().to(webhook)),
			)
			.await;
			let req = test::TestRequest::post().uri("/webhook/other").to_request();
			assert_eq!(
				test::call_service(&app_some, req).await.status(),
				StatusCode::NOT_FOUND
			);
		});
	}

	#[test]
	fn executes_webhook_without_leaking_script_path() {
		run_async(async {
			let dir = tempfile::tempdir().unwrap();
			let script = write_script(
				dir.path(),
				"secret_internal_hook.sh",
				"#!/bin/sh\nprintf 'hook-output-ok'\n",
			);
			let mut hooks = HashMap::new();
			hooks.insert("sign".to_owned(), script.clone());
			let app = test::init_service(
				App::new()
					.app_data(web::Data::new(Config {
						dir: dir.path().to_path_buf(),
						tls: None,
						webhooks: Some(hooks),
						jwt: None,
					}))
					.route("/webhook/{webhook}", web::post().to(webhook)),
			)
			.await;

			let req = test::TestRequest::post().uri("/webhook/sign").to_request();
			let resp = test::call_service(&app, req).await;
			assert_eq!(resp.status(), StatusCode::OK);
			let body = String::from_utf8_lossy(&test::read_body(resp).await).into_owned();
			assert!(body.contains("hook-output-ok"), "missing stdout: {body}");
			assert!(
				!body.contains("secret_internal_hook.sh"),
				"leaked script path: {body}"
			);
		});
	}

	#[test]
	fn webhook_errors_return_500_without_leaking_stderr_or_paths() {
		run_async(async {
			let dir = tempfile::tempdir().unwrap();
			let fail_script = write_script(
				dir.path(),
				"secret_fail_hook.sh",
				"#!/bin/sh\necho 'SECRET_HOOK_STDERR' >&2\nexit 42\n",
			);
			let mut hooks = HashMap::new();
			hooks.insert("fail".to_owned(), fail_script);
			hooks.insert(
				"missing".to_owned(),
				"/nonexistent/secret_missing_hook.sh".to_owned(),
			);

			let app = test::init_service(
				App::new()
					.app_data(web::Data::new(Config {
						dir: dir.path().to_path_buf(),
						tls: None,
						webhooks: Some(hooks),
						jwt: None,
					}))
					.route("/webhook/{webhook}", web::post().to(webhook)),
			)
			.await;

			let resp_fail = test::call_service(
				&app,
				test::TestRequest::post().uri("/webhook/fail").to_request(),
			)
			.await;
			assert_eq!(resp_fail.status(), StatusCode::INTERNAL_SERVER_ERROR);
			let body_fail = String::from_utf8_lossy(&test::read_body(resp_fail).await).into_owned();
			assert!(
				!body_fail.contains("SECRET_HOOK_STDERR"),
				"leaked stderr: {body_fail}"
			);
			assert!(
				!body_fail.contains("secret_fail_hook.sh"),
				"leaked path: {body_fail}"
			);

			let resp_missing = test::call_service(
				&app,
				test::TestRequest::post()
					.uri("/webhook/missing")
					.to_request(),
			)
			.await;
			assert_eq!(resp_missing.status(), StatusCode::INTERNAL_SERVER_ERROR);
			let body_missing =
				String::from_utf8_lossy(&test::read_body(resp_missing).await).into_owned();
			assert!(
				!body_missing.contains("secret_missing_hook.sh"),
				"leaked path: {body_missing}"
			);
		});
	}

	#[test]
	fn webhook_times_out_hung_script() {
		run_async(async {
			let dir = tempfile::tempdir().unwrap();
			let slow_script =
				write_script(dir.path(), "slow_hook.sh", "#!/bin/sh\nexec sleep 30\n");
			let mut hooks = HashMap::new();
			hooks.insert("hang".to_owned(), slow_script);
			let cfg = Config {
				dir: dir.path().to_path_buf(),
				tls: None,
				webhooks: Some(hooks),
				jwt: None,
			};

			let start = std::time::Instant::now();
			let resp = webhook_inner("hang".to_owned(), &cfg, Duration::from_millis(100)).await;
			assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
			assert!(
				start.elapsed() < Duration::from_secs(10),
				"webhook did not time out promptly"
			);
		});
	}
}
