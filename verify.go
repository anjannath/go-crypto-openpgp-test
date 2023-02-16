package clearsignverifier

import (
	"bytes"
    "log"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)


func VerifyClearSign(msg, pubkey string) error {
    b, _ := clearsign.Decode([]byte(msg))

    keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(pubkey))
    if err != nil {
        return err
    }
    signer, err := b.VerifySignature(keyring, &packet.Config{})
    if err != nil {
        return err
    }
    log.Println("Found valid signature from: ", signer.PrimaryIdentity().Name)
    return nil
}

func InspectKey(pubkey string) error {
    keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(pubkey))
    if err != nil {
        return err
    }

    for _, entity := range keyring {
        for name, id := range entity.Identities {
            log.Println(name, "::", id.Name)
        }
    }

    return nil
}
