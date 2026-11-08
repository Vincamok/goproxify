// h3probe : client HTTP/3 minimal du labo (curl d'Alpine n'a pas HTTP/3). Se connecte en QUIC à une adresse donnée avec un SNI donné,
// n'authentifie pas le serveur (certificat de test) et affiche « protocole code » puis les en-têtes demandés.
//
//	h3probe -addr 172.18.0.5:443 -sni lab-sec-tls.lab.test -path /whoami -H "X-Forwarded-For: 198.51.100.7" -show alt-svc
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type headers []string

func (h *headers) String() string     { return strings.Join(*h, ",") }
func (h *headers) Set(v string) error { *h = append(*h, v); return nil }

func main() {
	addr := flag.String("addr", "", "adresse UDP de la passerelle (ip:port)")
	sni := flag.String("sni", "", "nom d'hôte : SNI et en-tête Host")
	path := flag.String("path", "/", "chemin demandé")
	method := flag.String("method", "GET", "méthode")
	cert := flag.String("cert", "", "certificat client (PEM)")
	key := flag.String("key", "", "clé du certificat client (PEM)")
	show := flag.String("show", "", "en-têtes de réponse à afficher, séparés par des virgules")
	body := flag.Bool("body", false, "affiche le corps de la réponse")
	var hdrs headers
	flag.Var(&hdrs, "H", "en-tête de requête « Nom: valeur » (répétable)")
	flag.Parse()
	if *addr == "" || *sni == "" {
		fmt.Fprintln(os.Stderr, "usage : h3probe -addr ip:port -sni hôte [-path /] [-H 'N: v'] [-show en-tête,…] [-cert f -key f]")
		os.Exit(2)
	}

	tlsCfg := &tls.Config{ServerName: *sni, InsecureSkipVerify: true, NextProtos: []string{"h3"}} //nolint:gosec // certificat de test du labo
	if *cert != "" {
		c, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			fmt.Fprintln(os.Stderr, "erreur : certificat client :", err)
			os.Exit(2)
		}
		tlsCfg.Certificates = []tls.Certificate{c}
	}
	tr := &http3.Transport{
		TLSClientConfig: tlsCfg,
		Dial: func(ctx context.Context, _ string, cfg *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, *addr, cfg, qc)
		},
	}
	defer tr.Close()

	req, err := http.NewRequest(*method, "https://"+*sni+*path, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "erreur :", err)
		os.Exit(2)
	}
	for _, h := range hdrs {
		if k, v, ok := strings.Cut(h, ":"); ok {
			req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	resp, err := tr.RoundTrip(req.WithContext(ctx))
	if err != nil {
		fmt.Println("erreur", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	fmt.Println(resp.Proto, resp.StatusCode)
	for _, name := range strings.Split(*show, ",") {
		if name = strings.TrimSpace(name); name != "" {
			fmt.Printf("%s: %s\n", strings.ToLower(name), resp.Header.Get(name))
		}
	}
	if *body {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		fmt.Println(string(b))
	}
}
