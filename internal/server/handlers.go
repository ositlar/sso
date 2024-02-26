package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"ositlar.com/internal/token"
)

type Guid struct {
	Guid string `json:"guid"`
}

type Response struct {
	Status int    `json:"status"`
	Msg    string `json:"message"`
}

// Генерация пары токенов
func (s *server) CreateToken(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var guid Guid
	w.Header().Add("Content-Type", "application/json; charset=UTF-8")
	err := json.Unmarshal(body, &guid)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err)
		return
	}
	s.TokenResponse(guid.Guid, &w, s.store.InsertRefreshToken)
}

// Refresh
func (s *server) RefreshToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json; charset=UTF-8")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Errorln(err)
		s.error(w, http.StatusInternalServerError, err)
		return
	}
	var token token.Token
	err = json.Unmarshal(body, &token)
	if err != nil {
		s.logger.Errorln(err)
		s.error(w, http.StatusInternalServerError, err)
		return
	}
	if token.Refresh == "" || token.Access == "" {
		s.logger.Errorln(err)
		s.error(w, http.StatusBadRequest, errors.New("token is/are empty"))
		return
	}
	if claims, err := s.DeserAccessToken(token.Access); claims == nil || err != nil {
		s.logger.Errorln(err)
		s.error(w, http.StatusBadRequest, err)
		return
	} else {
		if err := s.CheckRefreshTokenValid(claims.Guid, token.Refresh); err == nil {
			s.TokenResponse(claims.Guid, &w, s.store.UpdateRefreshToken)
		} else {
			s.logger.Errorln(err)
			s.error(w, http.StatusBadRequest, err)
		}
	}
}

func (s *server) error(w http.ResponseWriter, code int, err error) {
	s.respond(w, code, map[string]string{"error": err.Error()})
}

func (s *server) respond(w http.ResponseWriter, code int, data interface{}) {
	w.WriteHeader(code)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}
