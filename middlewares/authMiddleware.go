package middlewares

import (
	"jwt-auth/helpers"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientToken := c.GetHeader("Authorization")
		if clientToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No Authorization header provided"})
			c.Abort()
			return
		}

		const bearerPrefix = "Bearer "
		if strings.HasPrefix(clientToken, bearerPrefix) {
			clientToken = strings.TrimPrefix(clientToken, bearerPrefix)
		}
		refresh_token, err := helpers.GetRefreshTokenFromCookie(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		claims, errorMsg := helpers.ValidateToken(clientToken, refresh_token, c)
		if errorMsg != "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err})
			c.Abort()
			return
		}

		c.Set("email", claims.Email)
		c.Set("first_name", claims.FirstName)
		c.Set("last_name", claims.LastName)
		c.Set("uid", claims.Uid)
		c.Set("user_type", claims.UserType)

		c.Next()
	}
}
