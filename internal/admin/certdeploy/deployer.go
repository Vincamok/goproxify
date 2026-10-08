// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package certdeploy

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Deployer déclenche les déploiements de certificats vers les cibles configurées. Chaque type de
// cible (webhook, ssh_exec…) est un module du registre : voir targets.go.
type Deployer struct {
	db     *sql.DB
	log    *slog.Logger
	client *http.Client
	// OnDeployFail est appelé quand un déploiement échoue (targetID, domain, typ, message).
	OnDeployFail func(targetID, domain, typ, message string)
}

func New(db *sql.DB, log *slog.Logger) *Deployer {
	return &Deployer{
		db:     db,
		log:    log,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

// TriggerForCert déclenche tous les targets on_renewal pour un cert donné.
func (d *Deployer) TriggerForCert(ctx context.Context, certID string) {
	rows, err := d.db.QueryContext(ctx,
		`SELECT id, type, config FROM cert_deploy_targets
		 WHERE cert_id=? AND trigger_on='on_renewal'`, certID)
	if err != nil {
		d.log.Error("certdeploy: query targets", "err", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id, typ, cfg string
		if err := rows.Scan(&id, &typ, &cfg); err != nil {
			continue
		}
		go d.runTarget(context.Background(), id, certID, typ, cfg)
	}
}

// TriggerTarget déclenche un target spécifique manuellement.
func (d *Deployer) TriggerTarget(ctx context.Context, targetID string) error {
	var certID, typ, cfg string
	err := d.db.QueryRowContext(ctx,
		`SELECT cert_id, type, config FROM cert_deploy_targets WHERE id=?`, targetID).
		Scan(&certID, &typ, &cfg)
	if err != nil {
		return fmt.Errorf("target introuvable: %w", err)
	}
	go d.runTarget(context.Background(), targetID, certID, typ, cfg)
	return nil
}

func (d *Deployer) runTarget(ctx context.Context, targetID, certID, typ, cfgJSON string) {
	var certPEM, keyPEM, domain string
	var expiresAt time.Time
	err := d.db.QueryRowContext(ctx,
		`SELECT domain, cert_pem, key_pem, expires_at FROM certs WHERE id=?`, certID).
		Scan(&domain, &certPEM, &keyPEM, &expiresAt)
	if err != nil {
		d.recordHistory(targetID, certID, "error", "cert introuvable: "+err.Error())
		return
	}

	status, msg, learned := d.deploy(ctx, typ, cfgJSON, Bundle{Domain: domain, CertPEM: certPEM, KeyPEM: keyPEM, ExpiresAt: expiresAt})
	d.saveLearned(ctx, targetID, cfgJSON, learned)

	d.recordHistory(targetID, certID, status, msg)
	_, _ = d.db.ExecContext(ctx,
		`UPDATE cert_deploy_targets SET last_deploy=CURRENT_TIMESTAMP, last_status=? WHERE id=?`,
		status, targetID)
	if status == "error" {
		d.log.Warn("certdeploy: deploy échoué", "target", targetID, "msg", msg)
		if d.OnDeployFail != nil {
			d.OnDeployFail(targetID, domain, typ, msg)
		}
	} else {
		d.log.Info("certdeploy: deploy ok", "target", targetID, "domain", domain)
	}
}

// deploy construit la cible du type demandé depuis sa configuration stockée et l'exécute.
func (d *Deployer) deploy(ctx context.Context, typ, cfgJSON string, b Bundle) (status, message string, learned map[string]any) {
	f, _, ok := registry.Lookup(typ)
	if !ok {
		return "error", "type non supporté: " + typ, nil
	}
	var cfg map[string]any
	_ = json.Unmarshal([]byte(cfgJSON), &cfg) // une config illisible est signalée par la fabrique du type
	t, err := f(cfg, Deps{Client: d.client})
	if err != nil {
		return "error", err.Error(), nil
	}
	status, message = t.Deploy(ctx, b)
	if l, ok := t.(Learner); ok {
		learned = l.Learned()
	}
	return status, message, learned
}

// saveLearned inscrit dans la configuration de la cible ce qu'elle a appris pendant le déploiement
// (ex. l'empreinte de la clé d'hôte SSH vue à la première connexion). Les champs déjà renseignés
// ne sont jamais écrasés.
func (d *Deployer) saveLearned(ctx context.Context, targetID, cfgJSON string, learned map[string]any) {
	if len(learned) == 0 {
		return
	}
	var cfg map[string]any
	if json.Unmarshal([]byte(cfgJSON), &cfg) != nil || cfg == nil {
		return
	}
	changed := false
	for k, v := range learned {
		if s, _ := cfg[k].(string); s == "" {
			cfg[k] = v
			changed = true
		}
	}
	if !changed {
		return
	}
	if b, err := json.Marshal(cfg); err == nil {
		_, _ = d.db.ExecContext(ctx, `UPDATE cert_deploy_targets SET config=? WHERE id=?`, string(b), targetID)
	}
}

func (d *Deployer) recordHistory(targetID, certID, status, message string) {
	_, _ = d.db.Exec(
		`INSERT INTO cert_deploy_history (id, target_id, cert_id, status, message)
		 VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?)`,
		targetID, certID, status, message)
}

func certFingerprint(certPEM []byte) string {
	h := sha256.Sum256(certPEM)
	return hex.EncodeToString(h[:])
}
