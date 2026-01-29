// Package main provides the esec CLI tool for encrypting and decrypting secrets.
package main

import "github.com/mscno/esec/cmd/esec/commands"

func main() {
	commands.Execute(VERSION)
}
