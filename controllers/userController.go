package controllers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"jwt-auth/database"
	"jwt-auth/helpers"
	"jwt-auth/models"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"golang.org/x/crypto/bcrypt"
)

var validate = validator.New()


func SetRefreshTokenCookie(c *gin.Context, refreshToken string) {
	// Set the refresh token as a cookie
	cookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Expires:  time.Now().Add(168 * time.Hour), // Set the expiration time
		HttpOnly: true,                           // HttpOnly makes the cookie inaccessible via JavaScript
		Secure: os.Getenv("ENV") != "dev",
		SameSite: http.SameSiteStrictMode,        // Adjust SameSite attribute based on your requirements
		Path:     "/",                            // Set the cookie to be accessible on all paths
	}

	http.SetCookie(c.Writer, cookie)
}

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}
func VerifyPassword(userPass string, foundPass string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(foundPass), []byte(userPass))
	var msg string
	check := true

	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			msg = "Incorrect password"
		} else {
			msg = "Error comparing passwords"
		}

		check = false
	}

	return check, msg
}

func Signup() gin.HandlerFunc {
	return func(c *gin.Context) {
		
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		var user models.User
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		validationError := validate.Struct(&user)
		if validationError != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationError.Error()})
			return
		}
		password := HashPassword(*user.Password)
		user.Password = &password
		uType:= "ADMIN"
		user.User_type = &uType 
		
		
		user.Created_at = time.Now()
		user.Updated_at = time.Now()
		
	    insertError := database.InsertUser(ctx,database.DB,&user)
		if insertError != nil {
			
			c.JSON(http.StatusInternalServerError, gin.H{"error": insertError.Error()})
			return
		}
		defer cancel()
		c.JSON(http.StatusOK, user)
		return

	}

}
func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		var user models.User
		var userFound models.User
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		query := "SELECT first_name,last_name,email,id,user_type,password_hash FROM users WHERE email = ?"
		row := database.DB.QueryRowContext(ctx, query, user.Email)

    
	err := row.Scan(&userFound.First_name,&userFound.Last_name,&userFound.Email,&userFound.ID,&userFound.User_type,&userFound.Password)

	switch {
	case err == sql.ErrNoRows:
		c.JSON(http.StatusUnauthorized,gin.H{"error":"user not found"})
		return
	case err != nil:
		c.JSON(http.StatusUnauthorized,gin.H{"error":"user not found"})
		return

	default:
		fmt.Printf("User found: %+v\n", user)
	}
	defer cancel()
		passwordIsValid, msg := VerifyPassword(*user.Password, *userFound.Password)
		defer cancel()
		if !passwordIsValid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": msg})
			return
		}
		token, refreshToken, _ := helpers.GenerateAllTokens(*userFound.Email, *userFound.First_name, *userFound.Last_name, *userFound.User_type, userFound.ID)
		

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Header("Authorization", "Bearer "+token)
        helpers.SetRefreshTokenCookie(c,refreshToken)
		c.JSON(http.StatusOK, userFound)

	}
}

// func GetUser() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		userId := c.Param("id")
// 		if err := helpers.MatchUserTypeToUid(c, userId); err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 			return
// 		}
// 		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
// 		var user models.User
// 		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
// 		defer cancel()
// 		if err != nil {
// 			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
// 			return
// 		}
// 		c.JSON(http.StatusOK, user)
// 	}
// }
func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		query := "SELECT id, first_name, email FROM users"

	// Query the database
	rows, err := database.DB.Query(query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	// Iterate over the rows
	for rows.Next() {
		var user models.User
		// Scan the result into the User struct
		err := rows.Scan(&user.ID, &user.First_name, &user.Email)
		if err != nil {
			log.Fatal(err)
		}
		// Print or process the user data as needed
		fmt.Printf("User: %+v\n", *user.Email)
	}

	// Check for errors from iterating over rows
	if err = rows.Err(); err != nil {
		log.Fatal(err)
	}
	return
	}

}
