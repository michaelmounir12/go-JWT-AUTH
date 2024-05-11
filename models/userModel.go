package models

import (
	"time"

)

type User struct{
	ID              int
	First_name		*string					`json:"first_name" validate:"required,min=2,max=100"`
	Last_name		*string					`json:"last_name" validate:"required,min=2,max=100"`
	Password		*string					`json:"Password" validate:"required,min=6"`
	Email			*string					`json:"email" validate:"email,required"`
	Phone			*string					`json:"phone" validate:"required"`
	User_type		*string					`json:"user_type" `
	Created_at		time.Time				`json:"created_at"`
	Updated_at		time.Time				`json:"updated_at"`
}