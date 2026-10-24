// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

func runLogs() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		q := url.Values{}
		for _, f := range []string{"-level", "-domain", "-ip", "-method", "-status", "-path", "-tls-ja3", "-tls-ja4", "-search", "-from", "-to", "-limit", "-page", "-source", "-node", "-cursor"} {
			if v := flagValue(args, f, ""); v != "" {
				q.Set(logsQueryKey(f), v)
			}
		}
		path := "/api/v1/logs"
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		var result map[string]any
		if _, err := client.DoJSON("GET", path, nil, &result); err != nil {
			fmt.Fprintf(os.Stderr, "logs list : %v\n", err)
			os.Exit(1)
		}
		printLogsNotes(result)
		entries, _ := result["entries"].([]any)
		if len(entries) == 0 {
			fmt.Println("(aucune entrée)")
			return
		}
		for _, e := range entries {
			entry, ok := e.(map[string]any)
			if !ok {
				continue
			}
			ts, _ := entry["ts"].(string)
			if len(ts) > 19 {
				ts = ts[:19]
			}
			level, _ := entry["level"].(string)
			domain, _ := entry["domain"].(string)
			method, _ := entry["method"].(string)
			reqPath, _ := entry["path"].(string)
			status := ""
			if s, ok := entry["status"].(float64); ok {
				status = fmt.Sprintf("%d", int(s))
			}
			ip, _ := entry["ip"].(string)
			fmt.Printf("%s  %-5s  %-3s  %-30s  %-7s  %-40s  %s\n",
				ts, level, status, domain, method, reqPath, ip)
		}
		if cursor, _ := result["cursor"].(string); cursor != "" {
			if more, _ := result["has_more"].(bool); more {
				fmt.Fprintf(os.Stderr, "Page suivante : -source edge -cursor %s\n", cursor)
			}
		}

	case "export":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		output := flagValue(args, "-output", "logs-export.csv")
		format := flagValue(args, "-format", "csv")
		q := url.Values{}
		q.Set("format", format)
		for _, f := range []string{"-level", "-domain", "-ip", "-tls-ja3", "-tls-ja4", "-from", "-to", "-source", "-node"} {
			if v := flagValue(args, f, ""); v != "" {
				q.Set(logsQueryKey(f), v)
			}
		}
		data, _, _, err := client.DoRaw("GET", "/api/v1/logs/export?"+q.Encode(), nil, "", 200)
		if err != nil {
			fmt.Fprintf(os.Stderr, "logs export : %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(output, data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "écriture fichier : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Logs exportés : %s (%d octets)\n", output, len(data))

	case "reveal-ip":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		entryID := flagValue(args, "-entry-id", "")
		entryRef := flagValue(args, "-entry-ref", "")
		reason := flagValue(args, "-reason", "")
		if (entryID == "") == (entryRef == "") || reason == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify logs reveal-ip (--entry-id <id> | --entry-ref <passerelle:type:id>) --reason \"motif légal\"")
			os.Exit(1)
		}
		body := map[string]any{"reason": reason}
		if entryRef != "" {
			body["entry_ref"] = entryRef
		} else {
			var idN float64
			fmt.Sscanf(entryID, "%f", &idN)
			body["entry_id"] = int64(idN)
		}
		var result map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/logs/reveal-ip", body, &result); err != nil {
			fmt.Fprintf(os.Stderr, "reveal-ip : %v\n", err)
			os.Exit(1)
		}
		ip, _ := result["ip"].(string)
		by, _ := result["requested_by"].(string)
		ts, _ := result["ts"].(string)
		fmt.Printf("IP réelle  : %s\nDemandé par : %s\nHorodatage : %s\nMotif       : %s\n", ip, by, ts, reason)

	case "delete":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		ip := flagValue(args, "-by-ip", "")
		user := flagValue(args, "-by-user", "")
		if (ip == "") == (user == "") {
			fmt.Fprintln(os.Stderr, "usage: goproxify logs delete --by-ip <ip> | --by-user <user_id> [--reason \"motif\"]")
			os.Exit(1)
		}
		path := "/api/v1/logs/by-ip/" + url.PathEscape(ip)
		if user != "" {
			path = "/api/v1/logs/by-user/" + url.PathEscape(user)
		}
		var body any
		if reason := flagValue(args, "-reason", ""); reason != "" {
			body = map[string]string{"reason": reason}
		}
		var result struct {
			Deleted    int64 `json:"deleted"`
			Bans       int64 `json:"bans_deleted"`
			BanHistory int64 `json:"ban_history_deleted"`
			GeoCache   int64 `json:"geoip_cache_deleted"`
			Counters   int64 `json:"ip_counters_deleted"`
			Gateways   []struct {
				NodeName string `json:"node_name"`
				Status   string `json:"status"`
				LogLines int64  `json:"log_lines"`
				BanRows  int64  `json:"ban_rows"`
			} `json:"gateways"`
		}
		if _, err := client.DoJSON("DELETE", path, body, &result); err != nil {
			fmt.Fprintf(os.Stderr, "delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%d entrée(s) supprimée(s)\n", result.Deleted)
		if result.Bans+result.BanHistory+result.GeoCache > 0 {
			fmt.Printf("%d ban(s), %d événement(s) de ban, %d entrée(s) GeoIP supprimé(s)\n",
				result.Bans, result.BanHistory, result.GeoCache)
		}
		for _, g := range result.Gateways {
			if g.Status == "erased" {
				fmt.Printf("passerelle %s : %d ligne(s) de logs, %d ligne(s) d'historique de bans effacée(s)\n", g.NodeName, g.LogLines, g.BanRows)
			} else {
				fmt.Printf("passerelle %s : injoignable, l'effacement lui sera rejoué à sa connexion\n", g.NodeName)
			}
		}

	case "subject-export":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		ip := flagValue(args, "-by-ip", "")
		user := flagValue(args, "-by-user", "")
		if (ip == "") == (user == "") {
			fmt.Fprintln(os.Stderr, "usage: goproxify logs subject-export --by-ip <ip> | --by-user <user_id> [--reason \"motif\"] [--output fichier.json]")
			os.Exit(1)
		}
		body := map[string]string{"ip": ip, "user_id": user}
		if ip == "" {
			delete(body, "ip")
		} else {
			delete(body, "user_id")
		}
		if reason := flagValue(args, "-reason", ""); reason != "" {
			body["reason"] = reason
		}
		payload, _ := json.Marshal(body)
		data, _, _, err := client.DoRaw("POST", "/api/v1/logs/subject-export", payload, "application/json", 200)
		if err != nil {
			fmt.Fprintf(os.Stderr, "logs subject-export : %v\n", err)
			os.Exit(1)
		}
		output := flagValue(args, "-output", "")
		if output == "" {
			os.Stdout.Write(data) //nolint:errcheck
			return
		}
		if err := os.WriteFile(output, data, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "écriture fichier : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Export RGPD écrit : %s (%d octets)\n", output, len(data))

	case "siem":
		runLogsSIEM()

	case "help":
		fmt.Print(`Usage: goproxify logs <sous-commande> [options]

Sous-commandes :
  list       Recherche dans les logs d'accès et système
  export     Exporte les logs en CSV ou JSON
  siem       Exporteur SIEM des passerelles : show, set, enable, disable, status (admin)
  reveal-ip  Révèle l'IP réelle d'une entrée pseudonymisée (scope gdpr:reveal requis)
  delete     Efface les logs d'une IP ou d'un utilisateur (RGPD Art. 17, admin, scope logs:write)
  subject-export  Exporte les données d'une IP ou d'un compte (RGPD Art. 15 et 20, admin, scope logs:write)

goproxify logs list
  [-level debug|info|warn|error]  Niveau de log
  [-domain <host>]                Filtrer par domaine/proxy
  [-ip <ip>]                      Filtrer par IP source
  [-method GET|POST|…]            Méthode HTTP
  [-status <code>]                Code HTTP (ex: 404, 5xx)
  [-path <préfixe>]               Chemin de la requête
  [-search <texte>]               Recherche libre
  [-from <RFC3339>]               Date de début
  [-to <RFC3339>]                 Date de fin
  [-limit <n>]                    Nombre de résultats (défaut: 50, 500 au plus avec -source edge)
  [-page <n>]                     Page (copie de l'Admin)
  [-source admin|edge]            admin (défaut) : copie de l'Admin ; edge : base de logs de chaque passerelle,
                                  fusionnée par l'Admin (ses propres logs compris)
  [-node <passerelle>]            Une seule passerelle (nom), avec -source edge
  [-cursor <jeton>]               Page suivante (jeton affiché par la page précédente), avec -source edge
  [-admin-url …] [-token …]

goproxify logs export
  [-format csv|json]  Format (défaut: csv)
  [-output <fichier>] Fichier de sortie (défaut: logs-export.csv)
  [-level …] [-domain …] [-ip …] [-from …] [-to …]
  [-source admin|edge] [-node <passerelle>]  (edge : au plus 100 000 lignes)
  [-admin-url …] [-token …]

goproxify logs siem show | set | enable | disable | status
  show                   Affiche la configuration (JSON, jetons des en-têtes masqués)
  set --file <fichier> | --stdin  Enregistre la configuration (JSON, comme « show ») ; un jeton laissé masqué est conservé
  enable | disable       Active ou éteint l'exporteur sans toucher aux destinations
  status                 État de chaque destination sur chaque passerelle : livraisons, retard, erreur
  [-admin-url …] [-token …]
  Chaque passerelle exporte seule vers le SIEM (syslog RFC 5424 TCP/TLS ou HTTP NDJSON) avec son propre curseur,
  même Admin éteint. Rôle admin.

goproxify logs reveal-ip
  --entry-id <id>    ID de l'entrée de log (visible dans la colonne id)
  --entry-ref <réf>  Référence d'une ligne de passerelle (« id » d'une entrée -source edge), à la place de --entry-id
  --reason "<motif>" Motif légal obligatoire (ex: "RGPD Art.17 DPO request")
  [-admin-url …] [-token …]
  Nécessite le scope gdpr:reveal.

goproxify logs delete
  --by-ip <ip> | --by-user <user_id>  Entrées à effacer (entrées pseudonymisées comprises)
  [--reason "<motif>"]                Motif inscrit au journal d'audit
  [-admin-url …] [-token …]
  Rôle admin ; avec un token API, scope logs:write.
  Une IP efface aussi ses bans, leur historique, son entrée GeoIP et ses lignes d'access log sur les passerelles.

goproxify logs subject-export
  --by-ip <ip> | --by-user <user_id>  Données à exporter (JSON : logs, bans, GeoIP, audit, profil du compte)
  [--reason "<motif>"]                Motif inscrit au journal d'audit
  [--output <fichier>]                Fichier de sortie (défaut : sortie standard)
  [-admin-url …] [-token …]
  Rôle admin ; avec un token API, scope logs:write.
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande logs inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify logs help")
		os.Exit(1)
	}
}

// logsQueryKey traduit une option de la CLI en paramètre de l'API de logs.
func logsQueryKey(flag string) string {
	switch key := strings.ReplaceAll(strings.TrimLeft(flag, "-"), "-", "_"); key {
	case "from":
		return "date_from"
	case "to":
		return "date_to"
	case "limit":
		return "page_size"
	case "node":
		return "node_name"
	default:
		return key
	}
}

// printLogsNotes signale, sur la sortie d'erreur, ce qui rend une réponse `source=edge` incomplète : des passerelles
// injoignables dont les lignes manquent, ou une recherche arrêtée par son délai.
func printLogsNotes(result map[string]any) {
	if un, _ := result["unreachable"].([]any); len(un) > 0 {
		var names []string
		for _, u := range un {
			if m, ok := u.(map[string]any); ok {
				name, _ := m["node_name"].(string)
				names = append(names, name)
			}
		}
		fmt.Fprintf(os.Stderr, "Résultats incomplets : passerelle(s) injoignable(s) : %s\n", strings.Join(names, ", "))
	}
	if partial, _ := result["partial"].(bool); partial {
		fmt.Fprintln(os.Stderr, "Recherche partielle : délai atteint avant d'avoir parcouru toute la période, resserrez la période ou ajoutez un filtre")
	}
}
