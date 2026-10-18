use anyhow::Result;
use filevault::{
    api::{self, Access, Context},
    config::Config,
    controller::Controller,
    transport::{Disabled, SshProbe, Transport},
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let (config, options) = Config::load()?;
    if let Some(path) = config.openapi {
        std::fs::write(
            path,
            format!("{}\n", serde_json::to_string_pretty(&api::openapi()?)?),
        )?;
        return Ok(());
    }
    let transport: Arc<dyn Transport> = if let Some(probe) = options.ssh_probe {
        Arc::new(
            SshProbe::new(probe).map_err(|_| anyhow::anyhow!("invalid SSH probe configuration"))?,
        )
    } else {
        Arc::new(Disabled)
    };
    let controller = Arc::new(Controller::new(
        transport,
        options.frontend_origin.unwrap_or_default(),
        std::time::Instant::now(),
    ));
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
                    controller,
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
    Ok(())
}
