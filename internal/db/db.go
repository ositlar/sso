package db

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"ositlar.com/internal/token"
)

var collection *mongo.Collection
var ctx = context.Background()

func InitDatabase(port string) {
	clientOptions := options.Client().ApplyURI(fmt.Sprintf("mongodb://localhost:%s/", port))
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	collection = client.Database("auth").Collection("refresh-tokens")
}

func InsertRefreshToken(refresh, guid string) error {
	token := token.RefreshToken{Refresh: refresh, Guid: guid, Time: time.Now().Add(60 * 24 * time.Hour)}
	_, err := collection.InsertOne(context.Background(), token)
	if err != nil {
		return err
	}
	return nil
}

func ReadRefreshToken(guid string) (*token.RefreshToken, error) {
	filter := bson.D{{"_id", guid}}
	var result *token.RefreshToken
	var err error
	if err = collection.FindOne(context.Background(), filter).Decode(&result); err == nil {
		return result, err
	}
	return nil, err
}

func UpdateRefreshToken(refresh, guid string) error {
	filter := bson.D{{"_id", guid}}
	update := bson.D{
		{"$set", bson.D{
			{"refresh", refresh},
			{"time", time.Now().Add(60 * 24 * time.Hour)},
		}},
	}
	_, err := collection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		return err
	}
	return nil
}
