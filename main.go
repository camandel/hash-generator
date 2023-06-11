package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

var userHash string

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		http.Redirect(w, r, "/", 301)
	case "POST":
		if err := r.ParseForm(); err != nil {
			fmt.Fprintf(w, "ParseForm() err: %v", err)
			return
		}
		email := r.FormValue("email")
		password := r.FormValue("password")
		if email == "user@example.com" && CheckPasswordHash(password, userHash) {
			token, _ := GenerateJWT(email)
			cookie := &http.Cookie{
				Name:   "token",
				Value:  token,
				MaxAge: 3600,
				Secure: false,
			}
			http.SetCookie(w, cookie)
			http.Redirect(w, r, "/", 301)
		} else {
			w.Write([]byte("Sorry, Unauthorized..."))
		}
	default:
		fmt.Fprintf(w, "Sorry, only GET and POST methods are supported.")
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	tokenCookie, err := r.Cookie("token")
	if err != nil {
		tmpl := template.Must(template.ParseFiles("templates/login.html"))
		tmpl.Execute(w, nil)
		return
	}

	claims, err2 := ValidateToken(tokenCookie.Value)
	if err2 != nil {
		w.Write([]byte("Sorry, your token is not valid..."))
		return
	}

	tmpl := template.Must(template.New("home.html").Funcs(template.FuncMap{
		"safe": func(s string) template.HTML { return template.HTML(s) },
	}).ParseFiles("templates/home.html"))
	tmpl.Execute(w, *claims)

}

func generateHashHandler(w http.ResponseWriter, r *http.Request) {
	tokenCookie, err := r.Cookie("token")
	if err != nil {
		tmpl := template.Must(template.ParseFiles("templates/login.html"))
		tmpl.Execute(w, nil)
		return
	}

	_, err2 := ValidateToken(tokenCookie.Value)
	if err2 != nil {
		w.Write([]byte("Sorry, your token is not valid.."))
		return
	}

	tmpl := template.Must(template.New("hash.html").Funcs(template.FuncMap{
		"safe": func(s string) template.HTML { return template.HTML(s) },
	}).ParseFiles("templates/hash.html"))

	switch r.Method {
	case "GET":
		tmpl.Execute(w, nil)
		return
	case "POST":
		if err := r.ParseForm(); err != nil {
			fmt.Fprintf(w, "ParseForm() err: %v", err)
			return
		}
		password := r.FormValue("password")
		if len([]rune(password)) >= 8 && len([]rune(password)) <= 50 {
			tmpl.Execute(w, GeneratePasswordHash(password))
			return
		}
		tmpl.Execute(w, "Password must have from 8 to 50 characters")
		return
	default:
		fmt.Fprintf(w, "Sorry, only GET and POST methods are supported.")
	}
}

func flagHandler(w http.ResponseWriter, r *http.Request) {
	tokenCookie, err := r.Cookie("token")
	if err != nil {
		tmpl := template.Must(template.ParseFiles("templates/login.html"))
		tmpl.Execute(w, nil)
		return
	}

	claims, err2 := ValidateToken(tokenCookie.Value)
	if err2 != nil {
		w.Write([]byte("Sorry, your token is not valid..."))
		return
	}

	if claims.Email != "admin@example.com" {
		w.Write([]byte("Sorry, only admin can access this page..."))
		return
	}

	w.Write([]byte(os.Getenv("FLAG")))
}

func main() {

	err := checkEnvVars()
	if err != nil {
		panic(err)
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	userHash = GeneratePasswordHash(os.Getenv("USER_PWD"))

	router := mux.NewRouter()

	router.HandleFunc("/", indexHandler)
	router.HandleFunc("/login", loginHandler)
	router.HandleFunc("/generateHash", generateHashHandler)
	router.HandleFunc("/flag", flagHandler)

	fs := http.FileServer(http.Dir("./static/"))
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))

	router.Use(loggingMiddleware)

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Printf("Listen on 0.0.0.0:%s", port)

	http.ListenAndServe(":"+port, router)
}
