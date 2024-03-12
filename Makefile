build: cmd/server/keylime_attestor/keylime_attestor.go cmd/agent/keylime_attestor/keylime_attestor.go
	go build -o keylime-attestor-server cmd/server/keylime_attestor/keylime_attestor.go
	go build -o keylime-attestor-agent cmd/agent/keylime_attestor/keylime_attestor.go

clean:
	go clean
	rm keylime-attestor-server
	rm keylime-attestor-agent
