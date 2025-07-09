package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"bytes"
	"os"
	"database/sql"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
    host     = "localhost"
    port     = 5432
    user     = "user"
    password = "123456789"
    dbname   = "auntification"
)

const webhookPort = "8080"
const webhookPath = "/webhook"

var db *sql.DB


var jwtSecretKey string

func getJWTKey() []byte {
	if envKey := os.Getenv("JWT_SECRET_KEY"); envKey != "" {
		return []byte(envKey)
	}
	
	if jwtSecretKey != "" {
		return []byte(jwtSecretKey)
	}
	
	panic("JWT secret key not configured")
}

func main() {
	http.HandleFunc("/gettoken", gettokenpair)
	http.HandleFunc("/refresh", refreshtoken)
	http.HandleFunc("/getguid", getguid)
	http.HandleFunc("/disreg", disreg)
	db_connect := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
        host, port, user, password, dbname)

    db, err := sql.Open("postgres", db_connect)
    if err != nil {
        fmt.Printf("Ошибка подключения к базе данных: %v", err)
    }
    defer db.Close()

    err = db.Ping()
    if err != nil {
        fmt.Printf("Ошибка ping к базе данных: %v", err)
    }

    fmt.Println("Успешное подключение к базе данных!")
}

func Generaterefreshtoken() (string, error) {
	token_bytes := make([]byte, 64)
	_, err := rand.Read(token_bytes)
	if err != nil {
		return "", fmt.Errorf("ошибка генерации токена: %v", err)
	}
	return base64.StdEncoding.EncodeToString(token_bytes), nil
}

func Hashrefreshtoken(refresh_token string) (string, error) {
	refresh_token_hash, err := bcrypt.GenerateFromPassword([]byte(refresh_token), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("ошибка хеширования токена: %v", err)
	}
	return string(refresh_token_hash), nil
}

func GenerateJWT(guid string, key []byte) (string, error) {
	jwt_token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"guid": guid,
	})
	jwt_token_string, err := jwt_token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("ошибка генерации JWT: %v", err)
	}
	return jwt_token_string, nil
}

func CheckJWT(tokenStr string, key []byte) (*jwt.Token, error) {
	jwt_token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
	_, ok := token.Method.(*jwt.SigningMethodHMAC)
	if  !ok {
			return nil, fmt.Errorf("не тот тип подписи")
		}
		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("ошибка проверки JWT: %v", err)
	}
	if !jwt_token.Valid {
		return nil, fmt.Errorf("JWT недействителен")
	}

	return jwt_token, nil
}

// @Summary      Получить пару токенов
// @Description  Генерирует access и refresh токены для нового пользователя (guid создается для нового пользователя)
// @Tags         auth
// @Produce      json
// @Success      200 {object} map[string]string
// @Failure      400 {string} string "необходим User-Agent"
// @Failure      500 {string} string "ошибка сервера"
// @Router       /gettoken [get]
func gettokenpair(writer http.ResponseWriter, request *http.Request) {
	guid := uuid.New().String()
	user_agent := request.Header.Get("User-Agent")
	if user_agent == "" {
		http.Error(writer, "необходим User-Agent", http.StatusBadRequest)
		return
	}
	ip_string, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		http.Error(writer, fmt.Sprintf("ошибка получения IP: %v", err), http.StatusInternalServerError)
		return
	}
	ip := net.ParseIP(ip_string)
	key := getJWTKey()
	refresh_token, err := Generaterefreshtoken()
	if err != nil {
		http.Error(writer, fmt.Sprintf("ошибка в генерации: %v", err), http.StatusInternalServerError)
		return
	
	}
	refresh_token_hash, err := Hashrefreshtoken(refresh_token)
	if err != nil {
		http.Error(writer, fmt.Sprintf("ошибка в хешировании: %v", err), http.StatusInternalServerError)
		return
	}
	jwt_token, err := GenerateJWT(guid, []byte(key))
	if err != nil {
		http.Error(writer, fmt.Sprintf("ошибка в JWT: %v", err), http.StatusInternalServerError)
		return
	}
	_, err = db.Exec("INSERT INTO auf (guid, refresh_token_hash, useragent, ip) VALUES ($1, $2, $3, $4)", guid, refresh_token_hash, user_agent, ip)
    if err != nil {
        fmt.Errorf("ошибка вставки в бд: %v", err)
    }
	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(map[string]string{
		"jwt":            jwt_token,
		"refresh_token":  refresh_token,})
}


// @Summary      Обновить пару токенов
// @Description  Генерирует новые access и refresh токены для существующего пользователя. Требует валидные JWT и refresh token из заголовков.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        jwt header string true "Текущий JWT токен"
// @Param        refresh_token header string true "Текущий refresh token"
// @Success      200 {object} map[string]string "Возвращает новую пару токенов"
// @Failure      400 {string} string "Необходимы JWT и refresh_token"
// @Failure      403 {string} string "Неверный токен/refresh_token или изменён User-Agent"
// @Failure      404 {string} string "Пользователь не найден"
// @Failure      500 {string} string "Ошибка сервера"
// @Router       /refreshtoken [post]
func refreshtoken(writer http.ResponseWriter, request *http.Request) {
	access_token := request.Header.Get("jwt")
	if access_token == "" {
		http.Error(writer, "необходим JWT", http.StatusBadRequest)
		return
	}
	refresh_token := request.Header.Get("refresh_token")
	if refresh_token == "" {
		http.Error(writer, "необходим refresh_token", http.StatusBadRequest)
		return
	}

	key := getJWTKey()
	jwt_token, err := CheckJWT(access_token, []byte(key))
	if err != nil {
		http.Error(writer, fmt.Sprintf("ошибка проверки JWT: %v", err), http.StatusForbidden)
		return
	}

	guid, correct := jwt_token.Claims.(jwt.MapClaims)["guid"].(string)
	if !correct {
		http.Error(writer, "ошибка получения GUID из JWT", http.StatusForbidden)
	}

	access_data := db.QueryRow("SELECT guid, refresh_token_hash, useragent, ip FROM auf WHERE guid = $1", guid)
	var guid_r, refresh_token_hash_r, user_agent_r, ip_r string
	err = access_data.Scan(&guid_r, &refresh_token_hash_r, &user_agent_r, &ip_r)
	if err == sql.ErrNoRows {
		http.Error(writer, "данного GUID не существует", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(writer, fmt.Sprintf("ошибка при попытке вытащить данные из бд: %v", err), http.StatusInternalServerError)
		return
	}

	
	ip_string, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		http.Error(writer, fmt.Sprintf("ошибка получения IP: %v", err), http.StatusInternalServerError)
		return
	}
	ip := net.ParseIP(ip_string)


	if guid_r != guid {
		http.Error(writer, "данного GUID не совпадают", http.StatusNotFound)
		return
	}

	user_agent := request.Header.Get("User-Agent")
	if user_agent_r != user_agent {
		http.Error(writer, "изменён user_agent", http.StatusForbidden)
		return
	}

	if ip.String() != ip_r {
    webhookURL := fmt.Sprintf("http://%s:%s%s", ip_r, webhookPort, webhookPath)
    payload := map[string]string{
        "guid":       guid,
        "old_ip":     ip_r,
        "new_ip":     ip.String(),
        "user_agent": user_agent,
    }
    body, _ := json.Marshal(payload)
    _, _ = http.Post(webhookURL, "application/json", bytes.NewBuffer(body))
	}

	err = bcrypt.CompareHashAndPassword([]byte(refresh_token_hash_r), []byte(refresh_token))
	if err != nil {
		http.Error(writer, "не парный refresh_token", http.StatusForbidden)
		return
	}

	jwt_token_new, err := GenerateJWT(guid, []byte(key))
	if err != nil {
		http.Error(writer, fmt.Sprintf("ошибка в JWT (refresh): %v", err), http.StatusInternalServerError)
		return
	}
	refresh_token, err = Generaterefreshtoken()
	if err != nil {
		http.Error(writer, fmt.Sprintf("ошибка в генерации (refresh): %v", err), http.StatusInternalServerError)
		return
	}
	refresh_token_hash, err := Hashrefreshtoken(refresh_token)
	if err != nil {
		http.Error(writer, fmt.Sprintf("ошибка в хешировании (refresh): %v", err), http.StatusInternalServerError)
		return
	}
	_, err = db.Exec("UPDATE auf SET refresh_token_hash = $1 WHERE guid = $2", refresh_token_hash, guid)
	if err != nil {
		http.Error(writer, fmt.Sprintf("ошибка обновления в бд: %v", err), http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(map[string]string{
		"jwt":            jwt_token_new,
		"refresh_token":  refresh_token,})
}


// @Summary      Получить GUID пользователя
// @Description  Извлекает GUID из валидного JWT токена (проверяет его наличие в БД)
// @Tags         auth
// @Produce      json
// @Param        jwt header string true "JWT токен"
// @Success      200 {object} map[string]string
// @Failure      400 {string} string "необходим JWT"
// @Failure      403 {string} string "неверный JWT или пользователь не существует"
// @Failure      500 {string} string "ошибка сервера"
// @Router       /getguid [get]
func getguid(writer http.ResponseWriter, request *http.Request) {
	jwt_token := request.Header.Get("jwt")
	if jwt_token == "" {
		http.Error(writer, "необходим JWT", http.StatusBadRequest)
		return
	}
	key := getJWTKey()
	token, err := CheckJWT(jwt_token, []byte(key))
	if err != nil {
		http.Error(writer, fmt.Sprintf("ошибка проверки JWT: %v", err), http.StatusForbidden)
		return
	}
	guid, correct := token.Claims.(jwt.MapClaims)["guid"].(string)
	access_data := db.QueryRow("SELECT * FROM auf WHERE guid = $1", guid)
	var access_data_parse []string
	err = access_data.Scan(&access_data_parse)
	if err == sql.ErrNoRows {
		http.Error(writer, "данного GUID не существует", http.StatusNotFound)
		return
	}
	if !correct {
		http.Error(writer, "ошибка получения GUID из JWT", http.StatusForbidden)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(map[string]string{
		"guid": guid,
	})
}


// @Summary      Удалить данные пользователя
// @Description  Удаляет запись пользователя из БД по GUID из JWT
// @Tags         auth
// @Produce      json
// @Param        jwt header string true "JWT токен"
// @Success      204 "Пользователь удалён"
// @Failure      400 {string} string "необходим JWT"
// @Failure      403 {string} string "неверный JWT"
// @Failure      500 {string} string "ошибка сервера"
// @Router       /disreg [delete]
func disreg(writer http.ResponseWriter, request *http.Request) {
	jwt_token := request.Header.Get("jwt")
	if jwt_token == "" {
		http.Error(writer, "необходим JWT", http.StatusBadRequest)
		return
	}

	key := getJWTKey()
	token, err := CheckJWT(jwt_token, []byte(key))
	if err != nil {
		http.Error(writer, fmt.Sprintf("ошибка проверки JWT: %v", err), http.StatusForbidden)
		return
	}

	guid, correct := token.Claims.(jwt.MapClaims)["guid"].(string)
	if !correct {
		http.Error(writer, "ошибка получения GUID из JWT", http.StatusForbidden)
		return
	}

	_, err = db.Exec("DELETE FROM auf WHERE guid = $1", guid)
	if err != nil {		
		http.Error(writer, fmt.Sprintf("ошибка удаления из бд: %v", err), http.StatusInternalServerError)
		return
	}
}