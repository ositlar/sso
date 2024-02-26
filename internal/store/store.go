package store

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"ositlar.com/internal/token"
)

type Store struct {
	Db  *mongo.Collection
	ctx context.Context
}

func NewStore(dataseUrl string) (*Store, error) {
	ctx := context.Background()
	clientOptions := options.Client().ApplyURI(dataseUrl)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, err
	}
	collection := client.Database("auth").Collection("refresh-tokens")
	s := &Store{
		Db:  collection,
		ctx: ctx,
	}
	return s, nil
}

func (s *Store) InsertRefreshToken(refresh, guid string) error {
	token := token.RefreshToken{Refresh: refresh, Guid: guid, Time: time.Now().Add(60 * 24 * time.Hour)}
	_, err := s.Db.InsertOne(context.Background(), token)
	if err != nil {
		return err
	}
	return nil
}

func (s *Store) FindRefreshToken(guid string) (*token.RefreshToken, error) {
	filter := bson.D{{"_id", guid}}
	var result *token.RefreshToken
	var err error
	if err = s.Db.FindOne(context.Background(), filter).Decode(&result); err == nil {
		return result, err
	}
	return nil, err
}

func (s *Store) UpdateRefreshToken(refresh, guid string) error {
	filter := bson.D{{"_id", guid}}
	update := bson.D{
		{"$set", bson.D{
			{"refresh", refresh},
			{"time", time.Now().Add(60 * 24 * time.Hour)},
		}},
	}
	_, err := s.Db.UpdateOne(context.Background(), filter, update)
	if err != nil {
		return err
	}
	return nil
}
