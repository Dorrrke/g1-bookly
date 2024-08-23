package models

import "time"

const CtxTimeout = 5 * time.Second

type User struct {
	UID      int    `json:"uId"`
	Name     string `json:"name"`
	Login    string `json:"login"`
	Password string `json:"password"`
}

type Book struct {
	BID    int    `json:"bId"`
	Lable  string `json:"lable"`
	Author string `json:"author"`
	UID    int    `json:"uId"`
}
