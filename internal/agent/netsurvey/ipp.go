package netsurvey

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// IPP: Get-Printer-Attributes (operation 0x000B) over plain HTTP to port
// 631.
//
// Why this is safe: Get-Printer-Attributes is the query every print
// dialog sends to show a printer's state and ink levels. It submits no
// job, cancels nothing, and changes no setting; this file builds no other
// operation. Only the listed attributes are requested, the answer is
// capped, redirects are not followed, and no proxy is used, so the
// request goes to the device and nowhere else.

const (
	ippPort       = 631
	ippMaxReply   = 64 << 10
	ippOpGetAttrs = 0x000B
)

// ippPaths are tried in order until one answers: the IPP Everywhere
// default, a common alternative, and the root CUPS answers for its
// default queue.
var ippPaths = []string{"/ipp/print", "/ipp/printer", "/"}

var ippRequested = []string{
	"printer-make-and-model", "printer-state", "printer-state-reasons", "printer-name",
	"printer-info", "printer-location", "printer-firmware-string-version", "printer-device-id",
	"marker-names", "marker-levels", "marker-colors",
}

// ippRequest encodes a Get-Printer-Attributes request for uri.
func ippRequest(uri string, requestID uint32) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x01, 0x01}) // IPP/1.1, which every printer speaks
	_ = binary.Write(&b, binary.BigEndian, uint16(ippOpGetAttrs))
	_ = binary.Write(&b, binary.BigEndian, requestID)
	b.WriteByte(0x01) // operation-attributes-tag
	attr := func(tag byte, name, value string) {
		b.WriteByte(tag)
		_ = binary.Write(&b, binary.BigEndian, uint16(len(name)))
		b.WriteString(name)
		_ = binary.Write(&b, binary.BigEndian, uint16(len(value)))
		b.WriteString(value)
	}
	attr(0x47, "attributes-charset", "utf-8")
	attr(0x48, "attributes-natural-language", "en")
	attr(0x45, "printer-uri", uri)
	for i, name := range ippRequested {
		if i == 0 {
			attr(0x44, "requested-attributes", name)
		} else {
			attr(0x44, "", name) // an additional value of the same attribute
		}
	}
	b.WriteByte(0x03) // end-of-attributes
	return b.Bytes()
}

// ippResponse is a decoded response: status and the attributes, each with
// its values as text or integers.
type ippResponse struct {
	Status uint16
	Attrs  map[string][]ippValue
}

type ippValue struct {
	Text string
	Int  int
	Num  bool
}

func parseIPPResponse(b []byte) (ippResponse, error) {
	r := ippResponse{Attrs: map[string][]ippValue{}}
	if len(b) < 9 {
		return r, fmt.Errorf("ipp: short reply")
	}
	if b[0] < 1 || b[0] > 2 {
		return r, fmt.Errorf("ipp: unknown version %d.%d", b[0], b[1])
	}
	r.Status = binary.BigEndian.Uint16(b[2:])
	p := b[8:]
	last := ""
	for len(p) > 0 {
		tag := p[0]
		p = p[1:]
		if tag == 0x03 {
			return r, nil
		}
		if tag < 0x10 {
			last = ""
			continue // a group delimiter
		}
		if len(p) < 2 {
			return r, fmt.Errorf("ipp: truncated")
		}
		nl := int(binary.BigEndian.Uint16(p))
		if len(p) < 2+nl+2 {
			return r, fmt.Errorf("ipp: truncated")
		}
		name := string(p[2 : 2+nl])
		p = p[2+nl:]
		vl := int(binary.BigEndian.Uint16(p))
		if len(p) < 2+vl {
			return r, fmt.Errorf("ipp: truncated")
		}
		val := p[2 : 2+vl]
		p = p[2+vl:]
		if name == "" {
			name = last
		}
		last = name
		if name == "" || len(r.Attrs) > 256 {
			continue
		}
		var v ippValue
		switch {
		case (tag == 0x21 || tag == 0x23) && len(val) == 4: // integer, enum
			v = ippValue{Int: int(int32(binary.BigEndian.Uint32(val))), Num: true}
		case tag == 0x22 && len(val) == 1: // boolean
			v = ippValue{Int: int(val[0]), Num: true}
		case tag >= 0x41 && tag <= 0x49 && tag != 0x43: // text, name, keyword, uri, charset, language, mime
			v = ippValue{Text: cleanString(string(val))}
		default:
			continue
		}
		if len(r.Attrs[name]) < 64 {
			r.Attrs[name] = append(r.Attrs[name], v)
		}
	}
	return r, fmt.Errorf("ipp: no end-of-attributes")
}

func (r ippResponse) text(name string) string {
	if v := r.Attrs[name]; len(v) > 0 {
		return v[0].Text
	}
	return ""
}

var ippStates = map[int]string{3: "idle", 4: "processing", 5: "stopped"}

// device maps the attributes onto a survey device.
func (r ippResponse) device(addr netip.Addr) *proto.NetSurveyDevice {
	d := &proto.NetSurveyDevice{IP: addr.String(), Protocols: []string{proto.NetSurveyIPP}}
	d.Model = r.text("printer-make-and-model")
	d.Name = r.text("printer-name")
	d.Description = r.text("printer-info")
	d.Location = r.text("printer-location")
	d.Firmware = r.text("printer-firmware-string-version")
	if id := r.text("printer-device-id"); id != "" {
		for _, kv := range strings.Split(id, ";") {
			k, v, _ := strings.Cut(kv, ":")
			switch strings.ToUpper(strings.TrimSpace(k)) {
			case "MFG", "MANUFACTURER":
				d.Vendor = strings.TrimSpace(v)
			case "MDL", "MODEL":
				if d.Model == "" {
					d.Model = strings.TrimSpace(v)
				}
			}
		}
	}
	if v := r.Attrs["printer-state"]; len(v) > 0 && v[0].Num {
		d.PrinterState = ippStates[v[0].Int]
	}
	for _, v := range r.Attrs["printer-state-reasons"] {
		if v.Text != "" && v.Text != "none" {
			d.PrinterReasons = append(d.PrinterReasons, v.Text)
		}
	}
	names, levels, colors := r.Attrs["marker-names"], r.Attrs["marker-levels"], r.Attrs["marker-colors"]
	for i := 0; i < len(names) && i < 32; i++ {
		s := proto.NetSurveySupply{Name: names[i].Text, Percent: -1}
		if i < len(levels) && levels[i].Num && levels[i].Int >= 0 && levels[i].Int <= 100 {
			s.Percent = levels[i].Int
		}
		if i < len(colors) {
			s.Color = colors[i].Text
		}
		d.Supplies = append(d.Supplies, s)
	}
	return d
}

func probeIPP(ctx context.Context, lim *Limiter, addr netip.Addr, timeout time.Duration) (*proto.NetSurveyDevice, error) {
	client := &http.Client{
		Timeout: timeout * 2,
		Transport: &http.Transport{
			Proxy:             nil, // the request is for the device, never a proxy
			DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	host := netip.AddrPortFrom(addr, ippPort).String()
	for i, path := range ippPaths {
		if err := lim.Wait(ctx); err != nil {
			return nil, err
		}
		uri := "ipp://" + host + path
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+host+path, bytes.NewReader(ippRequest(uri, uint32(i+1))))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/ipp")
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil // nothing (more) on 631: not a printer
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, ippMaxReply))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/ipp") {
			continue
		}
		r, err := parseIPPResponse(body)
		if err != nil {
			return nil, fmt.Errorf("ipp %s: %w", addr, err)
		}
		if r.Status >= 0x0100 { // not successful-ok*: try the next path
			continue
		}
		return r.device(addr), nil
	}
	return nil, nil
}
