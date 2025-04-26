package testutl

import (
	"log/slog"
	"math/rand"
	"net"
	"strconv"
	"time"
)

// GetPort Gets an available port to start a server
func GetPort() int {
	min := 1400
	max := 7000
	for {
		port := rand.Intn(max-min) + min
		lis, err := net.Listen("tcp", ":"+strconv.Itoa(port))
		if err == nil {
			err := lis.Close()
			if err != nil {
				slog.Error(err.Error())
			}
			time.Sleep(time.Millisecond * 50)
			return port
		}
	}
}
