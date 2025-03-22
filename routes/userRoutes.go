package routes

import (
	controllers "github/Mrudul111/FilmBoxdAuth/controller"

	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("/user/signUP", controllers.SignUp())
	incomingRoutes.POST("/user/login", controllers.Login())
	incomingRoutes.POST("/user/:user_id/createList", controllers.CreateList)
	incomingRoutes.POST("/user/:user_id/lists/:list_id/addMovie", controllers.AddMovieToList)
	incomingRoutes.GET("/user/:user_id/list/:list_id/movies", controllers.GetMoviesInList)
	incomingRoutes.POST("/user/:user_id/postReview", controllers.PostReviews)
	incomingRoutes.PUT("/users/:user_id/lists/:list_id/description", controllers.AddListDescription)
}
