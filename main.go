package main

import "github.com/dionebastos/vibesec/cmd"

func main() {
	cmd.FrontendHandler = frontendHandler
	cmd.Execute()
}
