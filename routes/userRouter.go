package routes

import(
	"github.com/gin-gonic/gin"
	"jwt-auth/middlewares"
	controller "jwt-auth/controllers"
)

func UserRoutes(incomingRoutes *gin.Engine){
	incomingRoutes.Use(middlewares.Authenticate())
	incomingRoutes.GET("/users",controller.GetUsers())
	// incomingRoutes.GET("/users/:id",controller.GetUser())

}
