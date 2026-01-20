package models

type Device struct {
	Name     string
	Addr     string
	Location string
}

type SlaveSearchResponse struct {
	Name string `json:"device_name"`
	Addr string `json:"ip"`
}
