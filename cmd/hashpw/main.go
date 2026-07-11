package main

import (
	"fmt"
	"os"
	"github.com/aefw/hapm/internal/security"
)

func main() {
	pw := "admin123"
	if len(os.Args) > 1 { pw = os.Args[1] }
	h, _ := security.HashPassword(pw)
	fmt.Println(h)
}
