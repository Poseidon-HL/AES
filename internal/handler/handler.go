package handler

import (
	"github.com/gin-gonic/gin"
	"strconv"
)

type Resp struct {
	Data   interface{} `json:"data"`
	ErrNo  int         `json:"errNo"`
	ErrMsg string      `json:"errMsg"`
}

func QueryStringByDefault(c *gin.Context, param string, dString string) string {
	return c.DefaultQuery(param, dString)
}

func QueryBoolByDefault(c *gin.Context, param string, dBool bool) bool {
	boolParam, err := strconv.ParseBool(c.Query(param))
	if err != nil {
		return dBool
	}
	return boolParam
}

func QueryIntByDefault(c *gin.Context, param string, dInt int) int {
	intParam, err := strconv.Atoi(c.Query(param))
	if err != nil {
		return dInt
	}
	return intParam
}
