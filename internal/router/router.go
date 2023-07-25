package router

import (
	"AES/internal/handler"
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
	r.GET("/getFile", handler.GetFile)
	r.GET("/getEncryptedFile", handler.GetEncryptedFile)
	// 静态文件服务
	r.StaticFile("/Ecb_encryption.png", "./resource/Ecb_encryption.png")
	if err := r.Run(); err != nil {
		panic(err)
	}
}
