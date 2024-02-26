package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"ositlar.com/internal/store"
	"ositlar.com/internal/token"
)

type server struct {
	router *mux.Router
	logger *logrus.Logger
	store  store.Store
}

func StartServer(config *Config) error {
	db, err := store.NewStore(config.DatabaseURL)
	if err != nil {
		return err
	}
	srv := newServer(*db)
	return http.ListenAndServe(config.BindAddr, srv)
}

func newServer(store store.Store) *server {
	s := &server{
		router: mux.NewRouter(),
		logger: logrus.New(),
		store:  store,
	}
	s.configureRouter()
	return s
}

func (s *server) configureRouter() {
	//...
	s.router.HandleFunc("/get", s.CreateToken).Methods("POST")      //Получение пары Access + Refresh
	s.router.HandleFunc("/refresh", s.RefreshToken).Methods("POST") //Refresh
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

type Claims struct {
	Guid string `json:"guid"`
	jwt.StandardClaims
}

func (s *server) TokenResponse(guid string, w *http.ResponseWriter, query func(string, string) error) {
	if guid == "" {
		s.logger.Errorln("guid is empty")
		s.error(*w, http.StatusBadRequest, errors.New("guid is empty"))
	}
	accessToken, err := s.CreateAccessToken(guid)
	if err != nil {
		s.logger.Errorln(err)
		s.error(*w, http.StatusInternalServerError, errors.New("access token generation failed"))
	}
	refreshToken, err := s.CreateRefreshToken(guid, query)
	if err != nil {
		s.logger.Errorln(err)
		s.error(*w, http.StatusInternalServerError, errors.New("refresh token generation failed"))
	}

	resposeToken, err := json.Marshal(token.Token{Status: 1, Access: accessToken, Refresh: refreshToken, Guid: guid})
	if err != nil {
		s.logger.Errorln(err)
		s.error(*w, http.StatusInternalServerError, errors.New("marshaling error"))
	}
	(*w).WriteHeader(http.StatusCreated)
	s.logger.Info(string(resposeToken))
	_, err = (*w).Write(resposeToken)
	if err != nil {
		s.logger.Errorln(err)
		s.error(*w, http.StatusInternalServerError, errors.New("internal error"))
	}

}

var secret = []byte("A&'/}Z57M(2hNg=;LE?")

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

func (s *server) CreateAccessToken(guid string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"guid": guid,
		"exp":  time.Now().Add(time.Minute * 45).Unix(), // <- ExpiresAt: time.Now().Add(time.Minute * 20).Unix(),
	})
	return token.SignedString(secret)
}

func (s *server) CreateRefreshToken(guid string, query func(string, string) error) (string, error) {
	var err error
	var tokenCrypt []byte
	token := make([]byte, 10)
	for i := range token {
		token[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	if tokenCrypt, err = bcrypt.GenerateFromPassword(token, 14); err == nil {
		if err = query(string(tokenCrypt), guid); err == nil {
			var tokenStr = base64.StdEncoding.EncodeToString(token)
			return tokenStr, err
		}
	}
	return "", err
}
func (s *server) DeserAccessToken(token string) (*Claims, error) {
	access, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("wrong signing method")
		}
		return secret, nil
	})

	if err != nil {
		return nil, err
	}

	if access.Valid {
		return access.Claims.(*Claims), nil
	} else if validationEror, ok := err.(*jwt.ValidationError); ok {
		if validationEror.Errors&jwt.ValidationErrorMalformed != 0 {
			return nil, fmt.Errorf("not a token")
		} else if validationEror.Errors&(jwt.ValidationErrorExpired) != 0 {
			return access.Claims.(*Claims), fmt.Errorf("token is expired")
		}
	}
	return nil, fmt.Errorf("token is broken")
}

func (s *server) CheckRefreshTokenValid(guid, refreshStr string) error {
	var err error
	if mongoToken, err := s.store.FindRefreshToken(guid); err == nil {
		if decodeToken, err := base64.RawStdEncoding.DecodeString(refreshStr); err == nil {
			if err = bcrypt.CompareHashAndPassword([]byte(mongoToken.Refresh), decodeToken); err == nil {
				return nil
			}
		}
	}
	return err
}
