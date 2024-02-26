package main

import (
	"flag"
	"log"

	"github.com/BurntSushi/toml"
	"ositlar.com/internal/server"
)

var (
	configPath string
)

func init() {
	flag.StringVar(&configPath, "config-flag", "configs/server.toml", "path to config file")
}

func main() {
	flag.Parse()
	config := server.NewConfig()
	_, err := toml.DecodeFile(configPath, config)
	if err != nil {
		log.Fatal(err)
	}

	if err := server.StartServer(config); err != nil {
		log.Fatal(err)
	}
}
