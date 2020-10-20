package main

import (
	"os"

	"github.com/jrwren/sadv"
)

func main() {
	user := os.Getenv("SASLUSER")
	password := os.Getenv("SASLPASS")
	retval, err := sadv.SASLauthdVerifyPassword("", user, password, "", "", "")
	if err != nil {
		os.Stdout.WriteString(err.Error())
		os.Stdout.WriteString("\n")
		os.Stdout.WriteString("from saslauthd:")
		os.Stdout.WriteString(retval)
		os.Stdout.WriteString("\n")
		return
	}
	os.Stdout.WriteString("OK Success.")
	os.Stdout.WriteString("\n")
	os.Stdout.WriteString("from saslauthd:")
	os.Stdout.WriteString(retval)
	os.Stdout.WriteString("\n")
}
