package main

// Usage:
// `vaultclient get <url-path-to-secret>`

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	vault "github.com/form3tech-oss/go-vault-client/v4/pkg/vaultclient"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "get",
				Usage: "get secret from a path",
				Action: func(c *cli.Context) error {
					secret, err := getSecret(c.Args().First())
					if err != nil {
						return err
					}

					fmt.Println(secret)
					return nil
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func getSecret(path string) (string, error) {
	err := vault.ConfigureDefault()
	if err != nil {
		return "", fmt.Errorf("could not configure vault: %w", err)
	}

	secrets, err := vault.ReadData(path)
	if err != nil {
		return "", fmt.Errorf("could not read secrets from path '%s': %w", path, err)
	}

	out, err := json.Marshal(secrets)
	if err != nil {
		return "", fmt.Errorf("could not marshal secrets to JSON: %w", err)
	}

	return string(out), nil
}
