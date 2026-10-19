-- Legacy history is preserved. Only new observations receive an expiry.
ALTER TABLE connection_checks ADD COLUMN expires_at INTEGER;
CREATE INDEX connection_checks_expiry ON connection_checks(expires_at);
