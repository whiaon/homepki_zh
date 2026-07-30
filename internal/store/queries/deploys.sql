-- Queries against the deploy_targets table. Backs internal/store/deploys.go.

-- name: InsertDeployTarget :exec
INSERT INTO deploy_targets (
    id, cert_id, name,
    cert_path, key_path, chain_path,
    mode, owner, "group",
    post_command, auto_on_rotate
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: InsertDeployTargetWithRunState :exec
INSERT INTO deploy_targets (
    id, cert_id, name,
    cert_path, key_path, chain_path,
    mode, owner, "group",
    post_command, auto_on_rotate,
    last_deployed_at, last_deployed_serial,
    last_status, last_error
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateDeployTarget :execrows
UPDATE deploy_targets
   SET name           = ?,
       cert_path      = ?,
       key_path       = ?,
       chain_path     = ?,
       mode           = ?,
       owner          = ?,
       "group"        = ?,
       post_command   = ?,
       auto_on_rotate = ?
   WHERE id = ? AND cert_id = ?;

-- name: GetDeployTarget :one
SELECT id, cert_id, name,
       cert_path, key_path, chain_path,
       mode, owner, "group",
       post_command, auto_on_rotate,
       last_deployed_at, last_deployed_serial,
       last_status, last_error, created_at
FROM deploy_targets
WHERE id = ?;

-- name: ListDeployTargetsByCertID :many
SELECT id, cert_id, name,
       cert_path, key_path, chain_path,
       mode, owner, "group",
       post_command, auto_on_rotate,
       last_deployed_at, last_deployed_serial,
       last_status, last_error, created_at
FROM deploy_targets
WHERE cert_id = ?
ORDER BY name, created_at;

-- name: DeleteDeployTarget :execrows
DELETE FROM deploy_targets
WHERE id = ? AND cert_id = ?;

-- name: RecordDeployRun :execrows
UPDATE deploy_targets
   SET last_deployed_at     = ?,
       last_deployed_serial = ?,
       last_status          = ?,
       last_error           = ?
   WHERE id = ?;
