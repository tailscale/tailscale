//go:generate protoc --go_out=paths=source_relative:. --go_opt=Mprofile.proto=tailscale.com/tstest/profilepb profile.proto

package profilepb
