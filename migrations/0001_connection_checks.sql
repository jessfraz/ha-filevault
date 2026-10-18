CREATE TABLE connection_checks (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint BLOB NOT NULL CHECK(length(fingerprint) = 32),
    started_at INTEGER NOT NULL DEFAULT (unixepoch()) CHECK(started_at > 0),
    finished_at INTEGER CHECK(finished_at >= started_at),
    state TEXT NOT NULL CHECK(state IN ('checking', 'complete', 'interrupted')),
    lan TEXT NOT NULL CHECK(length(lan) <= 512 AND json_valid(lan)),
    tailscale TEXT NOT NULL CHECK(length(tailscale) <= 512 AND json_valid(tailscale)),
    CHECK((state = 'checking') = (finished_at IS NULL))
);
CREATE INDEX connection_checks_profile_sequence
    ON connection_checks(fingerprint, sequence DESC);
