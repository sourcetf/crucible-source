// mmdb2jsonl：把 MaxMind DB (.mmdb) 全量导出为 JSONL 层格式。
package main

import (
	"encoding/json"
	"flag"
	"net"
	"os"
	"strconv"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

func broadcast(n net.IPNet) net.IP {
	out := make(net.IP, len(n.IP))
	for i := range n.IP {
		out[i] = n.IP[i] | ^n.Mask[i]
	}
	return out
}

func main() {
	mmdb := flag.String("f", "", "input .mmdb")
	out := flag.String("o", "", "output .jsonl")
	flag.Parse()
	if *mmdb == "" || *out == "" {
		os.Stderr.WriteString("usage: mmdb2jsonl -f x.mmdb -o x.jsonl\n")
		os.Exit(2)
	}
	db, err := maxminddb.Open(*mmdb)
	if err != nil {
		os.Stderr.WriteString("open: " + err.Error() + "\n")
		os.Exit(1)
	}
	defer db.Close()
	f, err := os.Create(*out)
	if err != nil {
		os.Stderr.WriteString("create: " + err.Error() + "\n")
		os.Exit(1)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	iter := db.Networks()
	n := 0
	var rec map[string]any
	for iter.Next() {
		sub, err := iter.Network(&rec)
		if err != nil {
			continue
		}
		line := map[string]any{
			"ip_start": sub.IP.String(),
			"ip_end":   broadcast(*sub).String(),
			"data":     rec,
		}
		if enc.Encode(line) != nil {
			break
		}
		n++
	}
	os.Stderr.WriteString("mmdb2jsonl: " + (*mmdb) + " rows=" + strconv.Itoa(n) + "\n")
}
