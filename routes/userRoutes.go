package routes

import (
	controllers "github/Mrudul111/FilmBoxdAuth/controller"

	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("/user/signUP", controllers.SignUp())
	incomingRoutes.POST("/user/login", controllers.Login())

}
