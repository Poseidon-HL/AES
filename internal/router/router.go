package router

import (
	"context"
	"github.com/gin-gonic/gin"
	"net/http"
)

func InitRouter(ctx context.Context) {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	// 静态文件服务
	r.StaticFile("/iwatch.png", "./resource/iwatch.png")
	if err := r.Run(); err != nil {
		panic(err)
	}
}
