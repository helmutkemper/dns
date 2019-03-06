package dns_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/benburkert/dns"
)

func ExampleClient_overrideNameServers() {
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,

		Dial: (&__dns.Client{
			Transport: &__dns.Transport{
				Proxy: __dns.NameServers{
					&net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53},
					&net.UDPAddr{IP: net.IPv4(8, 8, 4, 4), Port: 53},
				}.RoundRobin(),
			},
		}).Dial,
	}

	addrs, err := net.LookupHost("127.0.0.1.xip.io")
	if err != nil {
		panic(err)
	}

	for _, addr := range addrs {
		fmt.Println(addr)
	}
	// Output: 127.0.0.1
}

func ExampleClient_dnsOverTLS() {
	dnsLocal := __dns.OverTLSAddr{
		Addr: &net.TCPAddr{
			IP:   net.IPv4(192, 168, 8, 8),
			Port: 853,
		},
	}

	client := &__dns.Client{
		Transport: &__dns.Transport{
			Proxy: __dns.NameServers{dnsLocal}.Random(rand.Reader),

			TLSConfig: &tls.Config{
				ServerName: "dns.local",
			},
		},
	}

	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial:     client.Dial,
	}
}

func ExampleServer_authoritative() {
	customTLD := &__dns.Zone{
		Origin: "tld.",
		TTL:    time.Hour,
		SOA: &__dns.SOA{
			NS:     "dns.tld.",
			MBox:   "hostmaster.tld.",
			Serial: 1234,
		},
		RRs: __dns.RRSet{
			"1.app": {
				__dns.TypeA: {
					&__dns.A{A: net.IPv4(10, 42, 0, 1).To4()},
				},
				__dns.TypeAAAA: {
					&__dns.AAAA{AAAA: net.ParseIP("dead:beef::1")},
				},
			},
			"2.app": {
				__dns.TypeA: {
					&__dns.A{A: net.IPv4(10, 42, 0, 2).To4()},
				},
				__dns.TypeAAAA: {
					&__dns.AAAA{AAAA: net.ParseIP("dead:beef::2")},
				},
			},
			"3.app": {
				__dns.TypeA: {
					&__dns.A{A: net.IPv4(10, 42, 0, 3).To4()},
				},
				__dns.TypeAAAA: {
					&__dns.AAAA{AAAA: net.ParseIP("dead:beef::3")},
				},
			},
			"app": {
				__dns.TypeA: {
					&__dns.A{A: net.IPv4(10, 42, 0, 1).To4()},
					&__dns.A{A: net.IPv4(10, 42, 0, 2).To4()},
					&__dns.A{A: net.IPv4(10, 42, 0, 3).To4()},
				},
				__dns.TypeAAAA: {
					&__dns.AAAA{AAAA: net.ParseIP("dead:beef::1")},
					&__dns.AAAA{AAAA: net.ParseIP("dead:beef::2")},
					&__dns.AAAA{AAAA: net.ParseIP("dead:beef::3")},
				},
			},
		},
	}

	srv := &__dns.Server{
		Addr:    ":53351",
		Handler: customTLD,
	}

	go srv.ListenAndServe(context.Background())
	time.Sleep(100 * time.Millisecond) // wait for bind()

	addr, err := net.ResolveTCPAddr("tcp", srv.Addr)
	if err != nil {
		log.Fatal(err)
	}

	query := &__dns.Query{
		RemoteAddr: addr,
		Message: &__dns.Message{
			Questions: []__dns.Question{
				{
					Name:  "app.tld.",
					Type:  __dns.TypeA,
					Class: __dns.ClassIN,
				},
				{
					Name:  "app.tld.",
					Type:  __dns.TypeAAAA,
					Class: __dns.ClassIN,
				},
			},
		},
	}

	res, err := new(__dns.Client).Do(context.Background(), query)
	if err != nil {
		log.Fatal(err)
	}

	for _, answer := range res.Answers {
		switch rec := answer.Record.(type) {
		case *__dns.A:
			fmt.Println(rec.A)
		case *__dns.AAAA:
			fmt.Println(rec.AAAA)
		default:
			fmt.Println(rec)
		}
	}

	// Output: 10.42.0.1
	// 10.42.0.2
	// 10.42.0.3
	// dead:beef::1
	// dead:beef::2
	// dead:beef::3
}

func ExampleServer_recursive() {
	srv := &__dns.Server{
		Addr:    ":53352",
		Handler: __dns.HandlerFunc(__dns.Recursor),
		Forwarder: &__dns.Client{
			Transport: &__dns.Transport{
				Proxy: __dns.NameServers{
					&net.TCPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53},
					&net.TCPAddr{IP: net.IPv4(8, 8, 4, 4), Port: 53},
					&net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53},
					&net.UDPAddr{IP: net.IPv4(8, 8, 4, 4), Port: 53},
				}.RoundRobin(),
			},
			Resolver: new(__dns.Cache),
		},
	}

	go srv.ListenAndServe(context.Background())
	time.Sleep(100 * time.Millisecond) // wait for bind()

	addr, err := net.ResolveTCPAddr("tcp", srv.Addr)
	if err != nil {
		log.Fatal(err)
	}

	query := &__dns.Query{
		RemoteAddr: addr,
		Message: &__dns.Message{
			RecursionDesired: true,
			Questions: []__dns.Question{
				{
					Name:  "127.1.2.3.xip.io.",
					Type:  __dns.TypeA,
					Class: __dns.ClassIN,
				},
			},
		},
	}

	res, err := new(__dns.Client).Do(context.Background(), query)
	if err != nil {
		log.Fatal(err)
	}

	for _, answer := range res.Answers {
		switch rec := answer.Record.(type) {
		case *__dns.A:
			fmt.Println(rec.A)
		default:
			fmt.Println(rec)
		}
	}

	// Output: 127.1.2.3
}

func ExampleServer_recursiveWithZone() {
	customTLD := &__dns.Zone{
		Origin: "tld.",
		RRs: __dns.RRSet{
			"foo": {
				__dns.TypeA: {
					&__dns.A{A: net.IPv4(127, 0, 0, 1).To4()},
				},
			},
		},
	}

	mux := new(__dns.ResolveMux)
	mux.Handle(__dns.TypeANY, "tld.", customTLD)

	srv := &__dns.Server{
		Addr:    ":53353",
		Handler: mux,
		Forwarder: &__dns.Client{
			Transport: &__dns.Transport{
				Proxy: __dns.NameServers{
					&net.TCPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53},
					&net.TCPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53},
					&net.UDPAddr{IP: net.IPv4(8, 8, 4, 4), Port: 53},
					&net.UDPAddr{IP: net.IPv4(8, 8, 4, 4), Port: 53},
				}.RoundRobin(),
			},
			Resolver: new(__dns.Cache),
		},
	}

	go srv.ListenAndServe(context.Background())
	time.Sleep(100 * time.Millisecond) // wait for bind()

	addr, err := net.ResolveTCPAddr("tcp", srv.Addr)
	if err != nil {
		log.Fatal(err)
	}

	query := &__dns.Query{
		RemoteAddr: addr,
		Message: &__dns.Message{
			RecursionDesired: true,
			Questions: []__dns.Question{
				{
					Name:  "127.0.0.127.xip.io.",
					Type:  __dns.TypeA,
					Class: __dns.ClassIN,
				},
				{
					Name:  "foo.tld.",
					Type:  __dns.TypeA,
					Class: __dns.ClassIN,
				},
			},
		},
	}

	res, err := new(__dns.Client).Do(context.Background(), query)
	if err != nil {
		log.Fatal(err)
	}

	for _, answer := range res.Answers {
		switch rec := answer.Record.(type) {
		case *__dns.A:
			fmt.Println(rec.A)
		default:
			fmt.Println(rec)
		}
	}

	// Output: 127.0.0.127
	// 127.0.0.1
}
