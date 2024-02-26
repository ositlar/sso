package token

import (
	"time"
)

type RefreshToken struct {
	Guid    string    `bson:"_id"`
	Refresh string    `bson:"refresh"`
	Time    time.Time `bson:"time"`
}

type Token struct {
	Status  int    `json:"status"`
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
	Guid    string `json:"guid"`
}
