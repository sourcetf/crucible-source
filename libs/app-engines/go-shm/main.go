// Go shared-memory app engine server (OpenBSD: replaces libapp_go.so FFI).
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

const (
	magic     = 0x4352474f // 'CRGO'
	version   = 1
	slotCount = 64
	bodyCap   = 65536
	pathMax   = 512
	methodMax = 16

	stateIdle      = 0
	stateReqReady  = 1
	stateRespReady = 2
)

type header struct {
	Magic      uint32
	Version    uint32
	SlotCount  uint32
	SlotStride uint32
	BodyCap    uint32
}

type slotMeta struct {
	State       uint32
	HTTPStatus  uint32
	ReqBodyLen  uint32
	RespBodyLen uint32
	Method      [methodMax]byte
	Path        [pathMax]byte
}

func main() {
	shmPath := os.Getenv("GO_SHM_FILE")
	notify := os.Getenv("GO_SHM_NOTIFY_SOCKET")
	if shmPath == "" || notify == "" {
		fmt.Fprintln(os.Stderr, "go-shm-server: GO_SHM_FILE and GO_SHM_NOTIFY_SOCKET required")
		os.Exit(1)
	}

	f, err := os.OpenFile(shmPath, os.O_RDWR, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	stat, _ := f.Stat()
	size := int(stat.Size())
	data, err := syscall.Mmap(int(f.Fd()), 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		panic(err)
	}
	defer syscall.Munmap(data)

	hdr := (*header)(unsafe.Pointer(&data[0]))
	if hdr.Magic != magic {
		panic("bad shm magic")
	}
	stride := int(hdr.SlotStride)
	bodyCap := int(hdr.BodyCap)
	base := int(unsafe.Sizeof(header{}))

	_ = os.Remove(notify)
	ln, err := net.Listen("unix", notify)
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(true)
	}

	fmt.Fprintf(os.Stderr, "go-shm-server: shm=%s notify=%s slots=%d\n", shmPath, notify, hdr.SlotCount)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConn(conn, data, base, stride, bodyCap)
	}
}

func handleConn(conn net.Conn, data []byte, base, stride, bodyCap int) {
	defer conn.Close()
	var buf [5]byte
	for {
		if _, err := conn.Read(buf[:]); err != nil {
			return
		}
		slotID := binary.LittleEndian.Uint32(buf[0:4])
		op := buf[4]
		if op != 1 {
			continue
		}
		off := base + int(slotID)*stride
		meta := (*slotMeta)(unsafe.Pointer(&data[off]))
		if meta.State != stateReqReady {
			continue
		}
		method := cstr(meta.Method[:])
		path := cstr(meta.Path[:])
		reqLen := int(meta.ReqBodyLen)
		reqOff := off + int(unsafe.Sizeof(slotMeta{}))
		respOff := reqOff + bodyCap
		reqBody := data[reqOff : reqOff+reqLen]

		resp := fmt.Sprintf("hello from go-shm engine method=%s path=%s body_len=%d\n", method, path, len(reqBody))
		if len(resp) > bodyCap {
			resp = resp[:bodyCap]
		}
		copy(data[respOff:respOff+bodyCap], resp)
		meta.RespBodyLen = uint32(len(resp))
		meta.HTTPStatus = 200
		meta.State = stateRespReady

		binary.LittleEndian.PutUint32(buf[0:4], slotID)
		buf[4] = 2
		_, _ = conn.Write(buf[:])
	}
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
