// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import "testing"

// Vecteur croisé : cette enveloppe a été produite par PortalLogins.sealSecret (WebCrypto, internal/admin/ui/src/js/pages/
// portal-logins.js) avec la clé publique dérivée de « interop-master ». La passerelle, en Go, doit l'ouvrir : si l'un des deux
// côtés change de schéma (courbe, KDF, sel, info, format), ce test casse avant qu'un secret saisi dans l'Admin devienne
// illisible. Pour le régénérer : dériver la clé avec LoginSealPublicKey("interop-master"), puis sceller dans un navigateur.
const (
	interopMaster = "interop-master"
	interopPub    = "BFuEMQ0XbGoDA0hCxaghTxc3OxXV1szW6q+SFQ2/hzy4cAQVcac1qJRmEFLnE7ND0wqqjTqqQsa2SpCMfiEyKOQ="
	interopSealed = `{"v":1,"epk":"BHQ9kV59x9esSdBqoFqyUsJpWPWGytJm9PC3h61OOJhqP6a5w9XorozZZ8p6BXery3cIlbfpAkMzd+2+MVXiQ1g=","nonce":"qVQf05ywXsCUGdGX","ct":"BQjWoHGafUFnbrCSI9ts6SFAfEsHS+lw5wzLs6xeE0amEip3Sdc16I2YRavNJmOR5ZJ1Zpt1ZyG+oBGZjwhTtM9mY66vc3pUdK4mblD9Rj4gSNoOHrr4c3V9VXT+aPzElwtlQ9ciomxrXOc="}`
)

func TestOpensAnEnvelopeSealedByTheBrowser(t *testing.T) {
	pub, err := LoginSealPublicKey(interopMaster)
	if err != nil {
		t.Fatal(err)
	}
	if pub != interopPub {
		t.Fatalf("la dérivation de la clé publique a changé : %s", pub)
	}
	if err := ValidSealedSecret(interopSealed); err != nil {
		t.Fatalf("l'Admin doit accepter l'enveloppe du navigateur : %v", err)
	}
	got, err := OpenLoginSecret([]string{interopMaster}, interopSealed)
	if err != nil {
		t.Fatalf("la passerelle doit ouvrir l'enveloppe WebCrypto : %v", err)
	}
	if got.Password != "p@ss é/漢字" || got.PrivateKey != "-----BEGIN KEY-----\nabc\n-----END KEY-----\n" {
		t.Fatalf("contenu : %+v", got)
	}
	if _, err := OpenLoginSecret([]string{"autre"}, interopSealed); err == nil {
		t.Fatal("une autre clé maître ne doit pas l'ouvrir")
	}
}
