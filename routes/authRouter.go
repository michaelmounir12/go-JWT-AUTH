package routes

import (
	controller "jwt-auth/controllers"

	"github.com/gin-gonic/gin"
)

func AuthRoutes(incomingRoutes *gin.Engine){
	incomingRoutes.POST("signup",controller.Signup())
	incomingRoutes.POST("login",controller.Login())

}