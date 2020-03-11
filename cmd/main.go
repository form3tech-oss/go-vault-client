package main

// `vaultclient get <url-path-to-secret>`

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	vault "github.com/form3tech-oss/go-vault-client/pkg/vaultclient"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "get",
				Usage: "get secret from a path",
				Action: func(c *cli.Context) error {
					path := c.Args().First()

					err := vault.ConfigureDefault()
					if err != nil {
						return fmt.Errorf("could not configure vault: %w", err)
					}

					secrets, err := vault.ReadData(path)
					if err != nil {
						return fmt.Errorf("could not read secrets from path '%s': %w", path, err)
					}

					out, err := json.MarshalIndent(&secrets, "", "    ")
					if err != nil {
						return fmt.Errorf("could not marshal secrets to JSON: %w", err)
					}

					fmt.Print(string(out))
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
