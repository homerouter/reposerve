use crate::config::Config;

use actix_web::{web, HttpResponse};
use std::process::Command;

pub(crate) async fn webhook(webhook: web::Path<String>, config: web::Data<Config>) -> HttpResponse {
	let Some(ref webhooks) = config.webhooks else {
		log::warn!("received webhook request but webhooks are not configured");
		return HttpResponse::NotFound().body("webhooks not configured");
	};

	let Some(script) = webhooks.get(webhook.as_str()).cloned() else {
		return HttpResponse::NotFound().body("webhook not found");
	};

	let script_for_task = script.clone();
	match web::block(move || Command::new(&script_for_task).output()).await {
		Ok(Ok(output)) => {
			if output.status.success() {
				HttpResponse::Ok().body(format!(
					"{} executed with success: {}",
					script,
					String::from_utf8_lossy(&output.stdout)
				))
			} else {
				log::error!(
					"webhook {} exited with non-zero status {:?}: {}",
					script,
					output.status.code(),
					String::from_utf8_lossy(&output.stderr)
				);
				HttpResponse::InternalServerError().body(format!(
					"{} failed with exit code {:?}: {}",
					script,
					output.status.code(),
					String::from_utf8_lossy(&output.stderr)
				))
			}
		}
		Ok(Err(error)) => {
			log::error!("failed to execute {}: {}", script, error);
			HttpResponse::InternalServerError()
				.body(format!("failed to execute {}: {}", script, error))
		}
		Err(e) => {
			log::error!("blocking task failure for {}: {}", script, e);
			HttpResponse::InternalServerError().body(format!("task error: {}", e))
		}
	}
}
