mod args;
mod config;
mod directory;
mod upload;
mod webhook;

use crate::{
	args::Opts,
	config::Config,
	directory::directory_listing,
	upload::{upload, UploadLock},
	webhook::webhook,
};

use actix_files::Files;
use actix_schemeredirect_middleware::middleware::SchemeRedirect;
use actix_token_middleware::middleware::jwtauth::JwtAuth;
use actix_web::{
	middleware::Logger,
	web::{self, Data},
	App, HttpServer,
};
use anyhow::{anyhow, Context};
use rustls::{
	pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
	ServerConfig,
};

async fn serve(
	mut config: Config,
	secure: bool,
	addr: String,
	addrs: String,
	dev: bool,
) -> anyhow::Result<()> {
	// set keys from jwks endpoint
	if let Some(ref mut jwt) = config.jwt {
		jwt.set_keys()
			.await
			.map_err(|e| anyhow!("failed to get jkws keys {}", e))?;
	} else if dev {
		log::warn!(
			"no JWT configuration found to protect /webhook and /upload. Use only for development"
		);
	}
	// copy some values before config is moved
	let tls = config.tls.clone();
	// ponytail: global upload lock; shard per version/repo/arch if concurrent upload throughput matters
	let upload_lock = Data::new(UploadLock::new(()));

	// build the server
	let server = HttpServer::new(move || {
		let tls = config.tls.as_ref();
		// redirect only in dual protocoal and if a redirect config is provided
		let redirect_service =
			if let Some(redirect) = tls.filter(|_| !secure).and_then(|c| c.redirect.clone()) {
				log::info!(
					"redirect to https:{:?} for {:?} protocol(s)",
					redirect.port.unwrap_or(443),
					redirect.protocols
				);
				SchemeRedirect::new(
					redirect.protocols,
					tls.and_then(|o| o.hsts.clone()),
					redirect.port,
				)
			} else {
				// no redirection by default
				SchemeRedirect::default()
			};

		let mut app = App::new()
			.wrap(Logger::default())
			.wrap(redirect_service)
			.app_data(Data::new(config.clone()))
			.app_data(upload_lock.clone());

		// wrap /webhook and /upload inside JwtAuth if jwt is set
		if let Some(ref jwt) = config.jwt {
			app = app
				.service(
					web::resource("/webhook/{webhook}")
						.wrap(JwtAuth::new(jwt.clone()))
						.route(web::post().to(webhook)),
				)
				.service(
					web::resource("/upload")
						.wrap(JwtAuth::new(jwt.clone()))
						.route(web::post().to(upload)),
				)
		// otherwise mount /webhook and /upload with no protection only if dev mode is activated
		} else if dev {
			app = app
				.service(web::resource("/webhook/{webhook}").route(web::post().to(webhook)))
				.service(web::resource("/upload").route(web::post().to(upload)))
		}
		app.service(
			Files::new("/", &config.dir)
				.show_files_listing()
				.files_listing_renderer(directory_listing),
		)
	});

	// bind to https if tls configuration is present
	let mut server = if let Some(tls) = &tls {
		// information about hsts
		if let Some(hsts) = &tls.hsts {
			log::info!("send HSTS header: {:?}", hsts.to_string());
		}
		// Create tls config
		let crt_chain = CertificateDer::pem_file_iter(&tls.crt)
			.with_context(|| format!("unable to read {:?}", tls.crt))?
			.collect::<Result<Vec<_>, _>>()
			.map_err(|e| anyhow!("error reading certificate: {e}"))?;
		// Parse the key in RSA, PKCS8, or EC format
		let key = load_private_key(&tls.key)?;
		let tls_config = ServerConfig::builder()
			.with_no_client_auth()
			.with_single_cert(crt_chain, key)
			.with_context(|| "error setting crt/key pair")?;
		server
			.bind_rustls_0_23(&addrs, tls_config)
			.with_context(|| format!("unable to bind to https://{addrs}"))?
	} else {
		log::warn!("TLS is not activated. Use only for development");
		server
	};

	// bind to http if secure is false (default)
	server = if !secure {
		server
			.bind(&addr)
			.with_context(|| format!("unable to bind to http://{addr}"))?
	} else {
		server
	};

	if !secure {
		log::info!("listening on http://{addr}");
	}
	if tls.is_some() {
		log::info!("listening on https://{addrs}");
	}

	server.run().await?;
	Ok(())
}

fn load_private_key(path: &std::path::Path) -> anyhow::Result<PrivateKeyDer<'static>> {
	// first key found in RSA, PKCS8 or EC (SEC1) format
	PrivateKeyDer::from_pem_file(path).map_err(|e| anyhow!("invalid or no key in {path:?}: {e}"))
}

fn default_log_filter(verbose: bool) -> String {
	let default_level = if verbose { "debug" } else { "info" };
	format!(
		"reposerve={default_level},actix_web={default_level},actix_schemeredirect_middleware={default_level},actix_token_middleware={default_level}"
	)
}

fn main() -> anyhow::Result<()> {
	// read command line options
	let opts: Opts = args::from_env();

	// setup logging
	let default_filter = default_log_filter(opts.verbose);
	env_logger::init_from_env(
		env_logger::Env::new()
			.default_filter_or(default_filter)
			.default_write_style_or("auto"),
	);
	log::info!("{} v{}", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"));

	// read yaml config
	let config = Config::read(&opts.config)?;

	// start actix main loop
	let system = actix_web::rt::System::new();
	system.block_on(serve(config, opts.secure, opts.addr, opts.addrs, opts.dev))?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::path::Path;

	#[test]
	fn missing_tls_key_error_names_the_key_path() {
		let err = load_private_key(Path::new("/nonexistent/missing-tls.key")).unwrap_err();
		let msg = format!("{err:#}");
		assert!(
			msg.contains("missing-tls.key"),
			"expected missing key path in error, got: {msg}"
		);
	}

	#[test]
	fn default_log_filter_uses_valid_rust_module_target_names() {
		let filter = default_log_filter(true);
		assert!(filter.contains("actix_token_middleware=debug"));
		assert!(!filter.contains("actix-token-middleware"));
	}
}
