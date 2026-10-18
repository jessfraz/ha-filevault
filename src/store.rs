//! Bounded connection history. No target names, login data or raw errors.
use crate::{
    config::MacConfig,
    connectivity::{DnsCheck, EndpointCheck, SshCheck, TcpCheck},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use std::{path::Path, time::Duration};

pub const RETENTION_DAYS: u32 = 30;
pub const RETENTION_RUNS: u32 = 1000;
const RETENTION_SECONDS: i64 = RETENTION_DAYS as i64 * 86400;

#[derive(Debug, thiserror::Error)]
#[error("connection history unavailable")]
pub struct Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckError {
    DnsFailed,
    DnsTimedOut,
    InvalidAddress,
    TcpUnreachable,
    TcpTimedOut,
    SshUnavailable,
    SshTimedOut,
    Interrupted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EndpointObservation {
    pub dns: DnsCheck,
    pub tcp: TcpCheck,
    pub ssh: SshCheck,
    /// A fixed category only. Never an OS, DNS, SSH or authentication message.
    pub error: Option<CheckError>,
}
impl EndpointObservation {
    fn pending(configured: bool) -> Self {
        Self {
            dns: if configured {
                DnsCheck::NotChecked
            } else {
                DnsCheck::NotConfigured
            },
            tcp: TcpCheck::NotChecked,
            ssh: SshCheck::NotChecked,
            error: None,
        }
    }
}
impl From<&EndpointCheck> for EndpointObservation {
    fn from(check: &EndpointCheck) -> Self {
        let error = match (check.dns, check.tcp, check.ssh) {
            (DnsCheck::Failed, _, _) => Some(CheckError::DnsFailed),
            (DnsCheck::TimedOut, _, _) => Some(CheckError::DnsTimedOut),
            (DnsCheck::Rejected, _, _) => Some(CheckError::InvalidAddress),
            (_, TcpCheck::Unreachable, _) => Some(CheckError::TcpUnreachable),
            (_, TcpCheck::TimedOut, _) => Some(CheckError::TcpTimedOut),
            (_, _, SshCheck::Unavailable) => Some(CheckError::SshUnavailable),
            (_, _, SshCheck::TimedOut) => Some(CheckError::SshTimedOut),
            _ => None,
        };
        Self {
            dns: check.dns,
            tcp: check.tcp,
            ssh: check.ssh,
            error,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Checking,
    Complete,
    Interrupted,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ConnectionRun {
    pub sequence: i64,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub state: RunState,
    pub lan: EndpointObservation,
    pub tailscale: EndpointObservation,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct LastSuccess {
    /// An SSH handshake succeeded, including identities awaiting confirmation.
    pub reachable_at: Option<i64>,
    /// The observed server identity matched the existing trust store.
    pub verified_at: Option<i64>,
}
#[derive(Debug, Serialize, JsonSchema)]
pub struct EndpointSuccesses {
    pub lan: LastSuccess,
    pub tailscale: LastSuccess,
}
#[derive(Debug, Serialize, JsonSchema)]
pub struct HistoryPage {
    pub results: Vec<ConnectionRun>,
    pub next: Option<i64>,
    pub last_success: EndpointSuccesses,
    pub retention_days: u32,
    pub retention_runs: u32,
}

#[derive(sqlx::FromRow)]
struct RunRecord {
    sequence: i64,
    started_at: i64,
    finished_at: Option<i64>,
    state: String,
    lan: String,
    tailscale: String,
}
impl RunRecord {
    fn into_run(self) -> Result<ConnectionRun, Error> {
        let state = match self.state.as_str() {
            "checking" => RunState::Checking,
            "complete" => RunState::Complete,
            "interrupted" => RunState::Interrupted,
            _ => return Err(Error),
        };
        Ok(ConnectionRun {
            sequence: self.sequence,
            started_at: self.started_at,
            finished_at: self.finished_at,
            state,
            lan: serde_json::from_str(&self.lan).map_err(|_| Error)?,
            tailscale: serde_json::from_str(&self.tailscale).map_err(|_| Error)?,
        })
    }
}

#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
}

/// The same profile-match rule used by Shipments' persisted provider checks.
/// Hash only the endpoint configuration; never an SSH key or a credential.
pub fn connection_fingerprint(mac: &MacConfig) -> [u8; 32] {
    let mut hash = Sha256::new();
    for name in [&mac.host, &mac.tailscale_host] {
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name.as_bytes());
    }
    hash.update(mac.port.to_be_bytes());
    hash.finalize().into()
}

impl Store {
    pub async fn open(path: &Path) -> Result<Self, Error> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(30));
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .map_err(|_| Error)?;
        if sqlx::migrate!().run(&pool).await.is_err() {
            pool.close().await;
            return Err(Error);
        }
        let store = Self { pool };
        // A previous process cannot still finish its probes after a restart.
        let recovered = sqlx::query(
            "UPDATE connection_checks SET state='interrupted', finished_at=MAX(started_at, unixepoch()),
             lan=json_set(lan, '$.error', 'interrupted'),
             tailscale=json_set(tailscale, '$.error', 'interrupted') WHERE state='checking'"
        ).execute(&store.pool).await;
        if recovered.is_err() || store.prune().await.is_err() {
            store.pool.close().await;
            return Err(Error);
        }
        Ok(store)
    }

    async fn prune(&self) -> Result<(), Error> {
        sqlx::query(
            "DELETE FROM connection_checks WHERE state != 'checking' AND
            (started_at < unixepoch() - ? OR sequence NOT IN
              (SELECT sequence FROM connection_checks ORDER BY sequence DESC LIMIT ?))",
        )
        .bind(RETENTION_SECONDS)
        .bind(RETENTION_RUNS)
        .execute(&self.pool)
        .await
        .map_err(|_| Error)?;
        Ok(())
    }

    pub async fn begin(&self, mac: &MacConfig) -> Result<i64, Error> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|_| Error)?;
        let result = sqlx::query(
            "INSERT INTO connection_checks (fingerprint,state,lan,tailscale)
             VALUES (?,'checking',?,?)",
        )
        .bind(connection_fingerprint(mac).as_slice())
        .bind(
            serde_json::to_string(&EndpointObservation::pending(!mac.host.is_empty()))
                .map_err(|_| Error)?,
        )
        .bind(
            serde_json::to_string(&EndpointObservation::pending(
                !mac.tailscale_host.is_empty(),
            ))
            .map_err(|_| Error)?,
        )
        .execute(&mut *tx)
        .await
        .map_err(|_| Error)?;
        tx.commit().await.map_err(|_| Error)?;
        self.prune().await?;
        Ok(result.last_insert_rowid())
    }

    pub async fn finish(
        &self,
        sequence: i64,
        lan: &EndpointCheck,
        tailscale: &EndpointCheck,
    ) -> Result<ConnectionRun, Error> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|_| Error)?;
        let row = sqlx::query_as::<_, RunRecord>(
            "UPDATE connection_checks SET
            finished_at=MAX(started_at, unixepoch()), state='complete', lan=?, tailscale=?
            WHERE sequence=? AND state='checking'
            RETURNING sequence,started_at,finished_at,state,lan,tailscale",
        )
        .bind(serde_json::to_string(&EndpointObservation::from(lan)).map_err(|_| Error)?)
        .bind(serde_json::to_string(&EndpointObservation::from(tailscale)).map_err(|_| Error)?)
        .bind(sequence)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| Error)?;
        tx.commit().await.map_err(|_| Error)?;
        self.prune().await?;
        row.into_run()
    }

    pub async fn history(
        &self,
        fingerprint: &[u8; 32],
        before: Option<i64>,
        limit: u32,
    ) -> Result<HistoryPage, Error> {
        if !(1..=100).contains(&limit) || before.is_some_and(|n| n <= 0) {
            return Err(Error);
        }
        let mut rows = sqlx::query_as::<_, RunRecord>(
            "SELECT sequence,started_at,finished_at,state,lan,tailscale
            FROM connection_checks WHERE fingerprint=? AND started_at >= unixepoch() - ?
            AND (? IS NULL OR sequence < ?) ORDER BY sequence DESC LIMIT ?",
        )
        .bind(fingerprint.as_slice())
        .bind(RETENTION_SECONDS)
        .bind(before)
        .bind(before)
        .bind(limit + 1)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| Error)?;
        let more = rows.len() > limit as usize;
        rows.truncate(limit as usize);
        let next = more.then(|| rows.last().unwrap().sequence);
        let results = rows
            .into_iter()
            .map(RunRecord::into_run)
            .collect::<Result<Vec<_>, _>>()?;
        // Last success is calculated across all retained pages for this profile.
        let (lan_reached, lan_verified, tail_reached, tail_verified): (Option<i64>,Option<i64>,Option<i64>,Option<i64>) =
            sqlx::query_as("SELECT
              MAX(CASE WHEN json_extract(lan,'$.ssh') IN ('trusted','identity_needed') THEN finished_at END),
              MAX(CASE WHEN json_extract(lan,'$.ssh') = 'trusted' THEN finished_at END),
              MAX(CASE WHEN json_extract(tailscale,'$.ssh') IN ('trusted','identity_needed') THEN finished_at END),
              MAX(CASE WHEN json_extract(tailscale,'$.ssh') = 'trusted' THEN finished_at END)
              FROM connection_checks WHERE fingerprint=? AND state='complete' AND started_at >= unixepoch() - ?")
              .bind(fingerprint.as_slice()).bind(RETENTION_SECONDS).fetch_one(&self.pool).await.map_err(|_| Error)?;
        Ok(HistoryPage {
            results,
            next,
            last_success: EndpointSuccesses {
                lan: LastSuccess {
                    reachable_at: lan_reached,
                    verified_at: lan_verified,
                },
                tailscale: LastSuccess {
                    reachable_at: tail_reached,
                    verified_at: tail_verified,
                },
            },
            retention_days: RETENTION_DAYS,
            retention_runs: RETENTION_RUNS,
        })
    }

    pub async fn close(&self) -> Result<(), Error> {
        let checkpoint = sqlx::query_as::<_, (i64, i64, i64)>("PRAGMA wal_checkpoint(TRUNCATE)")
            .fetch_one(&self.pool)
            .await;
        self.pool.close().await;
        match checkpoint {
            Ok((0, _, _)) => Ok(()),
            _ => Err(Error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac() -> MacConfig {
        MacConfig {
            host: "private-host.example.invalid".into(),
            tailscale_host: "100.64.0.9".into(),
            username: "private-fixture-account".into(),
            ..Default::default()
        }
    }
    fn endpoint(ssh: SshCheck) -> EndpointCheck {
        EndpointCheck {
            host: "private-host.example.invalid".into(),
            port: 22,
            dns: DnsCheck::Resolved,
            tcp: TcpCheck::Connected,
            ssh,
        }
    }
    async fn save(
        store: &Store,
        mac: &MacConfig,
        lan: &EndpointCheck,
        tail: &EndpointCheck,
    ) -> ConnectionRun {
        let sequence = store.begin(mac).await.unwrap();
        store.finish(sequence, lan, tail).await.unwrap()
    }

    #[tokio::test]
    async fn successive_runs_persist_after_restart_and_match_only_the_same_endpoints() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.sqlite3");
        let mac = mac();
        let fingerprint = connection_fingerprint(&mac);
        let store = Store::open(&path).await.unwrap();
        let pass = save(
            &store,
            &mac,
            &endpoint(SshCheck::Trusted),
            &endpoint(SshCheck::IdentityNeeded),
        )
        .await;
        let failed = EndpointCheck {
            dns: DnsCheck::Failed,
            tcp: TcpCheck::NotChecked,
            ssh: SshCheck::NotChecked,
            ..endpoint(SshCheck::Trusted)
        };
        let fail = save(&store, &mac, &failed, &failed).await;
        assert!(fail.sequence > pass.sequence);
        store.close().await.unwrap();
        let store = Store::open(&path).await.unwrap();
        let page = store.history(&fingerprint, None, 1).await.unwrap();
        assert_eq!(page.results.len(), 1);
        assert_eq!(page.results[0].sequence, fail.sequence);
        assert_eq!(page.results[0].lan.error, Some(CheckError::DnsFailed));
        assert_eq!(page.last_success.lan.verified_at, pass.finished_at);
        assert_eq!(page.last_success.tailscale.reachable_at, pass.finished_at);
        assert_eq!(page.last_success.tailscale.verified_at, None);
        let older = store.history(&fingerprint, page.next, 1).await.unwrap();
        assert_eq!(older.results[0].sequence, pass.sequence);
        assert!(older.next.is_none());
        let mut changed = mac.clone();
        changed.port = 2222;
        assert!(
            store
                .history(&connection_fingerprint(&changed), None, 20)
                .await
                .unwrap()
                .results
                .is_empty()
        );
        changed = mac.clone();
        changed.host = "other.example.invalid".into();
        assert!(
            store
                .history(&connection_fingerprint(&changed), None, 20)
                .await
                .unwrap()
                .results
                .is_empty()
        );
        let migrations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(migrations, 1);
        store.close().await.unwrap();
        let bytes = std::fs::read(path).unwrap();
        for private in [mac.host, mac.tailscale_host, mac.username] {
            assert!(
                !bytes
                    .windows(private.len())
                    .any(|part| part == private.as_bytes())
            );
        }
    }

    #[tokio::test]
    async fn unfinished_checks_become_interrupted_without_fabricating_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.sqlite3");
        let store = Store::open(&path).await.unwrap();
        store.begin(&mac()).await.unwrap();
        store.close().await.unwrap();
        let store = Store::open(&path).await.unwrap();
        let page = store
            .history(&connection_fingerprint(&mac()), None, 20)
            .await
            .unwrap();
        let run = &page.results[0];
        assert!(matches!(run.state, RunState::Interrupted));
        assert!(run.finished_at.is_some());
        assert_eq!(run.lan.dns, DnsCheck::NotChecked);
        assert_eq!(run.lan.error, Some(CheckError::Interrupted));
        assert_eq!(page.last_success.lan.reachable_at, None);
        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn retention_is_bounded_by_age_and_total_runs_and_invalid_pages_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("history.sqlite3"))
            .await
            .unwrap();
        let first = save(
            &store,
            &mac(),
            &endpoint(SshCheck::Trusted),
            &endpoint(SshCheck::Trusted),
        )
        .await;
        let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
        for _ in 0..1005 {
            sqlx::query("INSERT INTO connection_checks(fingerprint,started_at,finished_at,state,lan,tailscale)
                SELECT fingerprint,started_at,finished_at,state,lan,tailscale FROM connection_checks WHERE sequence=?")
                .bind(first.sequence).execute(&mut *tx).await.unwrap();
        }
        tx.commit().await.unwrap();
        store.prune().await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM connection_checks")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(count, 1000);
        sqlx::query("UPDATE connection_checks SET started_at=unixepoch()-2678400,finished_at=unixepoch()-2678400
            WHERE sequence=(SELECT MIN(sequence) FROM connection_checks)").execute(&store.pool).await.unwrap();
        store.prune().await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM connection_checks")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(count, 999);
        for (before, limit) in [(Some(0), 20), (None, 0), (None, 101)] {
            assert!(
                store
                    .history(&connection_fingerprint(&mac()), before, limit)
                    .await
                    .is_err()
            );
        }
        store.close().await.unwrap();
    }
}
