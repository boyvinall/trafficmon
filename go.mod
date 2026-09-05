module github.com/boyvinall/trafficmon

go 1.22.0

require (
	github.com/cuonglm/quicsni v0.0.3
	github.com/dreadl0ck/tlsx v1.1.0
	github.com/gopacket/gopacket v1.3.1
	golang.org/x/sync v0.11.0
)

require (
	github.com/quic-go/quic-go v0.48.2 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	src.agwa.name/tlshacks v0.0.0-20231008131857-90d701ba3225 // indirect
)

replace github.com/dreadl0ck/tlsx => github.com/boyvinall/tlsx v1.1.1-go1.22
