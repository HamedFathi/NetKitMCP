//go:build tools

// Package main pins dependencies used by tool families during development.
package main

import (
	_ "codeberg.org/readeck/go-readability/v2"
	_ "github.com/Azure/go-ntlmssp"
	_ "github.com/JohannesKaufmann/html-to-markdown/v2"
	_ "github.com/PuerkitoBio/goquery"
	_ "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	_ "github.com/bufbuild/protocompile"
	_ "github.com/coder/websocket"
	_ "github.com/eclipse/paho.golang/paho"
	_ "github.com/eclipse/paho.mqtt.golang"
	_ "github.com/go-stomp/stomp/v3"
	_ "github.com/golang-jwt/jwt/v5"
	_ "github.com/icholy/digest"
	_ "github.com/jcmturner/gokrb5/v8/spnego"
	_ "github.com/jlaffaye/ftp"
	_ "github.com/miekg/dns"
	_ "github.com/mochi-mqtt/server/v2"
	_ "github.com/nats-io/nats-server/v2/server"
	_ "github.com/nats-io/nats.go"
	_ "github.com/pkg/sftp"
	_ "github.com/plgd-dev/go-coap/v3"
	_ "github.com/rabbitmq/amqp091-go"
	_ "github.com/tus/tusd/v2/pkg/handler"
	_ "github.com/twmb/franz-go/pkg/kfake"
	_ "github.com/twmb/franz-go/pkg/kgo"
	_ "golang.org/x/crypto/ssh"
	_ "golang.org/x/net/html/charset"
	_ "golang.org/x/oauth2"
	_ "google.golang.org/grpc"
	_ "google.golang.org/protobuf/types/dynamicpb"
)
