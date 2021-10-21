package main

import (
	"log"
	"net/http"
)

func main() {
	log.Printf("listening on :9090")
	err := http.ListenAndServe(":9090", http.FileServer(http.Dir(".")))
	if err != nil {
		log.Fatal(err)
		return
	}
}
