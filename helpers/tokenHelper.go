package helpers

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	
)

type SignedDetails struct {
	Email     string
	FirstName string
	LastName  string
	Uid       int
	UserType  string
	jwt.MapClaims
}


var SECRET_KEY string = os.Getenv("SECRET_KEY")

func ValidateToken(signedToken string,refreshToken string,c *gin.Context) (claims *SignedDetails, msg string) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&SignedDetails{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SECRET_KEY), nil
		},
	)

	if err != nil {
		msg = err.Error()
		return nil, msg
	}

	claims, ok := token.Claims.(*SignedDetails)
	if !ok {
		msg = fmt.Sprintf("the token is invalid")
		return nil, msg
	}

	expTime, err := claims.GetExpirationTime()
	if err != nil {
		msg = fmt.Sprintf("error getting expiration time: %s", err.Error())
		return nil, msg
	}
    fmt.Println(expTime)
	if expTime.Unix() < time.Now().Unix() {
		err := CheckRefreshToken(c,refreshToken)
		if err!=nil {
			return nil,err.Error()
		}
		
		msg = fmt.Sprintf("token is expired")
		return nil, msg
	}

	return claims, msg
}

func CheckRefreshToken(c *gin.Context,refreshToken string) (err error) {
    token, err := jwt.ParseWithClaims(
        refreshToken,
        &SignedDetails{},
        func(token *jwt.Token) (interface{}, error) {
            return []byte(SECRET_KEY), nil
        },
    )

    if err != nil {
        return err
    }

    claims, ok := token.Claims.(*SignedDetails)
    if !ok {
        return fmt.Errorf("the token is invalid")
    }

    expTime, err := claims.GetExpirationTime()
    if err != nil {
        return fmt.Errorf("error getting expiration time: %s", err.Error())
    }
	fmt.Println(expTime)
    if expTime.Unix() < time.Now().Unix() {
		
		return fmt.Errorf("token has expired")
	}

    newToken,newRefreshToken,err := GenerateAllTokens(claims.FirstName,claims.Email,claims.LastName,claims.UserType,claims.Uid)
	c.Header("Authorization", "Bearer "+newToken)
    SetRefreshTokenCookie(c,newRefreshToken)
    return nil
}

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
func GenerateAllTokens(firstName string, email string, lastName string, userType string, userID int) (string, string, error) {
	accessClaims := &SignedDetails{
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		Uid:       userID,
		UserType:  userType,
		MapClaims: jwt.MapClaims{

			"exp": time.Now().Local().Add(time.Millisecond * time.Duration(24)).Unix(), // Token will expire in 24 hours
			"iat": time.Now().Local().Unix(),
		},
	}
	refreshClaims := &SignedDetails{
		MapClaims: jwt.MapClaims{

			"exp": time.Now().Local().Add(time.Microsecond * time.Duration(168)).Unix(), // Token will expire in 24 hours
			"iat": time.Now().Local().Unix(),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString([]byte(SECRET_KEY))
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString([]byte(SECRET_KEY))
	if err != nil {
		log.Panic(err)

	}
	return token, refreshToken, err

}

func GetRefreshTokenFromCookie(c *gin.Context) (string, error) {
	cookie, err := c.Request.Cookie("refresh_token")
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}