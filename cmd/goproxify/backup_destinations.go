package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

func fmtOptTime(t *time.Time) string {
	if t == nil {
		return "jamais"
	}
	return t.Local().Format(time.RFC3339)
}

type cliDestination struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Enabled   bool              `json:"enabled"`
	Config    map[string]string `json:"config"`
	Retention int               `json:"retention"`
}

func runBackupDestinations() {
	action := subcommand(os.Args, 3)
	args := parseFlags(os.Args[4:])
	client, err := newAdminClient(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	fail := func(err error) {
		fmt.Fprintf(os.Stderr, "backup destinations %s : %v\n", action, err)
		os.Exit(1)
	}
	switch action {
	case "list", "":
		var ds []cliDestination
		if _, err := client.DoJSON("GET", "/api/v1/backups/destinations", nil, &ds); err != nil {
			fail(err)
		}
		if len(ds) == 0 {
			fmt.Println("(aucune destination)")
			return
		}
		fmt.Printf("%-36s  %-18s  %-7s  %-6s  %-9s  %s\n", "ID", "NOM", "TYPE", "ACTIF", "RÉTENTION", "CIBLE")
		for _, d := range ds {
			target := d.Config["path"] + d.Config["url"] + d.Config["endpoint"]
			fmt.Printf("%-36s  %-18s  %-7s  %-6v  %-9d  %s\n", d.ID, truncate(d.Name, 18), d.Type, d.Enabled, d.Retention, target)
		}

	case "add":
		d := cliDestination{
			Name: flagValue(args, "-name", ""), Type: flagValue(args, "-type", ""), Enabled: true,
			Config: map[string]string{},
		}
		d.Retention, _ = strconv.Atoi(flagValue(args, "-retention", "0"))
		for flag, key := range map[string]string{
			"-path": "path", "-url": "url", "-username": "username", "-password": "password",
			"-endpoint": "endpoint", "-bucket": "bucket", "-region": "region", "-prefix": "prefix",
			"-access-key": "access_key", "-secret-key": "secret_key", "-path-style": "path_style",
		} {
			if v := flagValue(args, flag, ""); v != "" {
				d.Config[key] = v
			}
		}
		var saved cliDestination
		if _, err := client.DoJSON("POST", "/api/v1/backups/destinations", d, &saved); err != nil {
			fail(err)
		}
		fmt.Printf("Destination créée : %s (%s)\n", saved.Name, saved.ID)

	case "test":
		id := flagValue(args, "-id", subcommand(os.Args, 4))
		var res struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		if _, err := client.DoJSON("POST", "/api/v1/backups/destinations/"+id+"/test", map[string]any{}, &res); err != nil {
			fail(err)
		}
		if !res.OK {
			fmt.Fprintf(os.Stderr, "test échoué : %s\n", res.Error)
			os.Exit(1)
		}
		fmt.Println("destination fonctionnelle (écriture, lecture, suppression)")

	case "delete":
		id := flagValue(args, "-id", subcommand(os.Args, 4))
		if _, err := client.DoJSON("DELETE", "/api/v1/backups/destinations/"+id, nil, nil); err != nil {
			fail(err)
		}
		fmt.Println("destination supprimée (les copies déjà déposées sont conservées)")

	default:
		fmt.Fprintf(os.Stderr, "sous-commande inconnue : %q (list | add | test | delete)\n", action)
		os.Exit(1)
	}
}
