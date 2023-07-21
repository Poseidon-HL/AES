package main

import (
	"AES/internal/router"
	"context"
)

func main() {
	ctx := context.Background()
	router.InitRouter(ctx)
}
