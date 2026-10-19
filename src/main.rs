use anyhow::Result;
use filevault::{
    api::{self, Access, Context},
    config::Config,
    controller::Controller,
    profiles,
    store::Store,
    supervisor::Supervisor,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let (config, options) = Config::load()?;
    if let Some(input) = &config.migrate_options {
        filevault::migration::write(input, config.migration_output.as_ref().unwrap())?;
        println!("Connection options migrated. Original file preserved; output is owner-only.");
        return Ok(());
    }
    if let Some(path) = config.openapi {
        std::fs::write(
            path,
            format!("{}\n", serde_json::to_string_pretty(&api::openapi()?)?),
        )?;
        return Ok(());
    }
    let profiles = profiles::build(&options, config.options.as_deref());
    let store = Store::open(&config.database)
        .await?
        .with_retention_days(config.history_days);
    for error in &profiles.errors {
        eprintln!("{error}");
    }
    let mut controller = Controller::new(
        profiles.transport,
        options.frontend_origin.unwrap_or_default(),
        std::time::Instant::now(),
    )
    .with_configuration_errors(profiles.errors)
    .with_configuration_notes(profiles.notes)
    .with_connection(profiles.connection);
    if let Some(runtime) = profiles.runtime {
        controller = controller.with_runtime(runtime);
    }
    let background_checks = profiles.connectivity.clone();
    if let Some(connectivity) = profiles.connectivity {
        controller = controller
            .with_connectivity(Arc::new((*connectivity).clone().with_store(store.clone())));
    }
    if let Some(observer) = profiles.observer {
        controller = controller.with_observer(observer);
    }
    if let Some(manual) = profiles.manual {
        controller = controller.with_manual(manual);
    }
    let controller = Arc::new(controller);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let monitor = background_checks.map(|checks| {
        let checks = (*checks).clone().with_store(store.clone());
        let stopped = stopped.clone();
        tokio::spawn(async move {
            checks
                .monitor(
                    std::time::Duration::from_secs(config.check_interval_seconds),
                    stopped,
                )
                .await;
        })
    });
    let pairing = if options.auto_pairing {
        if let (Some(supervisor), Some(token)) =
            (Supervisor::from_environment()?, config.status_token.clone())
        {
            Some(tokio::spawn(supervisor.run(token, stopped)))
        } else {
            None
        }
    } else {
        None
    };
    let status = config
        .status_token
        .map(|token| {
            api::start(
                config.bind,
                Arc::new(Context {
                    access: Access::Status {
                        token_hash: Sha256::digest(token).into(),
                    },
                    controller: controller.clone(),
                }),
            )
        })
        .transpose()?;
    let ingress = config
        .ingress_bind
        .map(|bind| {
            api::start(
                bind,
                Arc::new(Context {
                    access: Access::Ingress {
                        peer: config.ingress_peer,
                        users: options.allowed_user_ids.into_iter().collect(),
                    },
                    controller: controller.clone(),
                }),
            )
        })
        .transpose()?;
    anyhow::ensure!(
        status.is_some() || ingress.is_some(),
        "no authenticated listener configured"
    );
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { r=tokio::signal::ctrl_c()=>r?, _=term.recv()=>{} }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    if let Some(server) = status {
        server
            .close()
            .await
            .map_err(|_| anyhow::anyhow!("close status listener"))?;
    }
    if let Some(server) = ingress {
        server
            .close()
            .await
            .map_err(|_| anyhow::anyhow!("close ingress listener"))?;
    }
    let _ = stop.send(true);
    if let Some(monitor) = monitor {
        monitor
            .await
            .map_err(|_| anyhow::anyhow!("close connection monitor"))?;
    }
    controller.drain_connections().await;
    if let Some(pairing) = pairing {
        pairing
            .await
            .map_err(|_| anyhow::anyhow!("close app discovery"))?;
    }
    store.close().await?;
    Ok(())
}
