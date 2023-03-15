package controllers

import (
	"jwt-tokens-mysql/initializers"
	"jwt-tokens-mysql/models"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func SignUp(c *gin.Context) {

	// get the email/pass of the request bdy

	var body struct {
		Email    string
		Password string
	}
	if c.Bind(&body) != nil {

		c.JSON(http.StatusBadRequest, gin.H{

			"error": "failed to read the body",
		})
		return

	}

	// hash the password

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {

		c.JSON(http.StatusBadRequest, gin.H{

			"message": "Failed to Hash the password",
		})

	}

	// create the user

	user := models.User{Email: body.Email, Password: string(hash)}
	result := initializers.DB.Create(&user)

	if result.Error != nil {

		c.JSON(http.StatusBadRequest, gin.H{

			"error": "Failed To create User",
		})

		return

	}

	// respond

	c.JSON(http.StatusOK, gin.H{})

}

func Login(c *gin.Context) {

	// get the email and request of the body

	var body struct {
		Email    string
		Password string
	}

	if c.Bind(&body) != nil {

		c.JSON(http.StatusBadRequest, gin.H{

			"error": "Failed to read body",
		})

		return

	}

	// look for requested user

	var user models.User

	initializers.DB.First(&user, "email=?", body.Email)

	if user.ID == 0 {

		c.JSON(http.StatusBadRequest, gin.H{

			"error": "Invalid Email",
		})
		return

	}

	// compare sent in pass with saved user pass hash

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {

		c.JSON(http.StatusBadRequest, gin.H{

			"error": "Invalid Password",
		})
		return

	}

	//generate a jwt token

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{

		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	// sign and get the complete encoded token as a string using the secret key

	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {

		c.JSON(http.StatusBadRequest, gin.H{

			"error": "Failed to Create Token",
		})

		return
	}

	// send it back

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{

		//"token": tokenString,
	})

}

func Validate(c *gin.Context) {

	user, _ := c.Get("user")

	c.JSON(http.StatusOK, gin.H{

		"message": user,
	})

}
