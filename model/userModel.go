package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type List struct {
	List_id          string  `json:"list_id"`
	List_name        string  `json:"list_name"`
	Movies           []Movie `json:"movies"`
	List_description string  `json:"description"`
}
type Movie struct {
	Title      string  `json:"title" validate:"required"`
	Genre      string  `json:"genre" validate:"required"`
	Link       string  `json:"link"`
	UserRating float64 `json:"user_rating"`
	AvgRating  float64 `json:"avg_rating"`
}

type Review struct {
	Movie   []Movie `json:"movie"`
	Rating  float64 `json:"rating" validate:"required,min=0,max=5"`
	Comment string  `json:"comment"`
	UserID  string  `json:"user_id"`
}

type User struct {
	ID            primitive.ObjectID `bson:"_id"`
	First_name    *string            `json:"first_name" validate:"required,min=2,max=100"`
	Last_name     *string            `json:"last_name" validate:"required,min=2,max=100"`
	Password      *string            `json:"Password" validate:"required,min=6"`
	Email         *string            `json:"email" validate:"email,required"`
	Phone         *string            `json:"phone" validate:"required"`
	Token         *string            `json:"token"`
	Refresh_token *string            `json:"refresh_token"`
	Created_at    time.Time          `json:"created_at"`
	Updated_at    time.Time          `json:"updated_at"`
	User_id       string             `json:"user_id"`
	Followers     int                `json:"followers"`
	Following     int                `json:"following"`
	List          []List             `json:"list"`
	UserReview    []Review           `json:"user_reviews"`
}
