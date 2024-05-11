package main

import (
	"jwt-auth/database"
	routes "jwt-auth/routes"
	"log"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	
	port := os.Getenv("PORT")
	if port==""{
	 port = "3000"}
	 

	router:=gin.New()
	database.Init()
	router.Use(gin.Logger())
    routes.AuthRoutes(router)
	routes.UserRoutes(router)
	defer func() {
		if err := database.DB.Close(); err != nil {
			log.Println("Error closing database:", err)
		}
	}()
	router.Run(":"+port)
}
