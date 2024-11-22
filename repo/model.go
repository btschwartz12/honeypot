package repo

import (
	"fmt"
	"time"

	"github.com/samber/mo"

	maindb "github.com/btschwartz12/honeypot/repo/db"
	cowriedb "github.com/btschwartz12/honeypot/repo/db/cowrie"
)

var (
	EstTimezone *time.Location
)

func init() {
	var err error
	EstTimezone, err = time.LoadLocation("America/New_York")
	if err != nil {
		panic(fmt.Errorf("failed to load timezone: %w", err))
	}
}

type EstTime struct {
	time.Time
}

func (e EstTime) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", e.In(EstTimezone).Format("2006-01-02 15:04:05 MST"))), nil
}

type Auth struct {
	ID        int64
	SessionID string
	Success   bool
	Username  string
	Password  string
	Timestamp EstTime
}

type Download struct {
	ID        int64
	SessionID string
	Timestamp EstTime
	Url       string
	Outfile   mo.Option[string]
	Shasum    mo.Option[string]
}

type Input struct {
	ID        int64
	SessionID string
	Timestamp EstTime
	Realm     mo.Option[string]
	Success   bool
	Input     string
}

type Ipforward struct {
	ID        int64
	SessionID string
	Timestamp EstTime
	DstIp     string
	DstPort   int64
}

type Ipforwardsdatum struct {
	ID        int64
	SessionID string
	Timestamp EstTime
	DstIp     string
	DstPort   int64
	Data      string
}

type Keyfingerprint struct {
	ID          int64
	SessionID   string
	Username    string
	Fingerprint string
}

type Param struct {
	ID        int64
	SessionID string
	Arch      string
}

type Ttylog struct {
	ID        int64
	SessionID string
	Log       string
	Size      int64
}

type Session struct {
	ID              string
	StartTime       EstTime
	EndTime         mo.Option[EstTime]
	Ip              string
	TermSize        mo.Option[string]
	SensorIp        mo.Option[string]
	ClientVersion   mo.Option[string]
	Auths           []Auth
	Downloads       []Download
	Inputs          []Input
	Ipforwards      []Ipforward
	Ipforwardsdata  []Ipforwardsdatum
	Keyfingerprints []Keyfingerprint
	Params          []Param
	Ttylogs         []Ttylog
}

func (s *Session) FromDb(
	session cowriedb.GetSessionRow,
	auths []cowriedb.Auth,
	downloads []cowriedb.Download,
	inputs []cowriedb.Input,
	ipforwards []cowriedb.Ipforward,
	ipforwardsdata []cowriedb.Ipforwardsdatum,
	keyfingerprints []cowriedb.Keyfingerprint,
	params []cowriedb.Param,
	ttylogs []cowriedb.Ttylog,
) {
	s.ID = session.ID
	s.StartTime = EstTime{session.Starttime}
	if session.Endtime.Valid {
		s.EndTime = mo.Some(EstTime{session.Endtime.Time})
	}
	s.Ip = session.Ip
	if session.Termsize.Valid {
		s.TermSize = mo.Some(session.Termsize.String)
	}
	if session.SensorIp.Valid {
		s.SensorIp = mo.Some(session.SensorIp.String)
	}
	if session.ClientVersion.Valid {
		s.ClientVersion = mo.Some(session.ClientVersion.String)
	}
	s.Auths = make([]Auth, len(auths))
	for i, auth := range auths {
		a := Auth{}
		a.ID = auth.ID
		a.SessionID = auth.Session
		a.Success = auth.Success == 1
		a.Username = auth.Username
		a.Password = auth.Password
		a.Timestamp = EstTime{auth.Timestamp}
		s.Auths[i] = a
	}
	s.Downloads = make([]Download, len(downloads))
	for i, download := range downloads {
		d := Download{}
		d.ID = download.ID
		d.SessionID = download.Session
		d.Timestamp = EstTime{download.Timestamp}
		d.Url = download.Url
		if download.Outfile.Valid {
			d.Outfile = mo.Some(download.Outfile.String)
		}
		if download.Shasum.Valid {
			d.Shasum = mo.Some(download.Shasum.String)
		}
		s.Downloads[i] = d
	}
	s.Inputs = make([]Input, len(inputs))
	for i, input := range inputs {
		in := Input{}
		in.ID = input.ID
		in.SessionID = input.Session
		in.Timestamp = EstTime{input.Timestamp}
		if input.Realm.Valid {
			in.Realm = mo.Some(input.Realm.String)
		}
		if input.Success.Valid {
			in.Success = input.Success.Int64 == 1
		}
		in.Input = input.Input
		s.Inputs[i] = in
	}
	s.Ipforwards = make([]Ipforward, len(ipforwards))
	for i, ipforward := range ipforwards {
		ipf := Ipforward{}
		ipf.ID = ipforward.ID
		ipf.SessionID = ipforward.Session
		ipf.Timestamp = EstTime{ipforward.Timestamp}
		ipf.DstIp = ipforward.DstIp
		ipf.DstPort = ipforward.DstPort
		s.Ipforwards[i] = ipf
	}
	s.Ipforwardsdata = make([]Ipforwardsdatum, len(ipforwardsdata))
	for i, ipforwardsdatum := range ipforwardsdata {
		ipfd := Ipforwardsdatum{}
		ipfd.ID = ipforwardsdatum.ID
		ipfd.SessionID = ipforwardsdatum.Session
		ipfd.Timestamp = EstTime{ipforwardsdatum.Timestamp}
		ipfd.DstIp = ipforwardsdatum.DstIp
		ipfd.DstPort = ipforwardsdatum.DstPort
		ipfd.Data = ipforwardsdatum.Data
		s.Ipforwardsdata[i] = ipfd
	}
	s.Keyfingerprints = make([]Keyfingerprint, len(keyfingerprints))
	for i, keyfingerprint := range keyfingerprints {
		kf := Keyfingerprint{}
		kf.ID = keyfingerprint.ID
		kf.SessionID = keyfingerprint.Session
		kf.Username = keyfingerprint.Username
		kf.Fingerprint = keyfingerprint.Fingerprint
		s.Keyfingerprints[i] = kf
	}
	s.Params = make([]Param, len(params))
	for i, param := range params {
		p := Param{}
		p.ID = param.ID
		p.SessionID = param.Session
		p.Arch = param.Arch
		s.Params[i] = p
	}
	s.Ttylogs = make([]Ttylog, len(ttylogs))
	for i, ttylog := range ttylogs {
		t := Ttylog{}
		t.ID = ttylog.ID
		t.SessionID = ttylog.Session
		t.Log = ttylog.Ttylog
		t.Size = ttylog.Size
		s.Ttylogs[i] = t
	}
}

func (s *Session) SuccessfulLogin() bool {
	for _, auth := range s.Auths {
		if auth.Success {
			return true
		}
	}
	return false
}

type GetSessionsFilter struct {
	StartTimeLt     mo.Option[time.Time]
	StartTimeGt     mo.Option[time.Time]
	Ip              mo.Option[string]
	Limit           mo.Option[int64]
	Offset          mo.Option[int64]
	SuccessfulLogin mo.Option[bool]
}

func (f *GetSessionsFilter) ToDb() maindb.GetSessionIdsParams {
	p := maindb.GetSessionIdsParams{}
	if f.StartTimeLt.IsPresent() {
		p.StartTimeLt = f.StartTimeLt.MustGet().UTC().Format("2006-01-02T15:04:05.000000Z")
	}
	if f.StartTimeGt.IsPresent() {
		p.StartTimeGt = f.StartTimeGt.MustGet().UTC().Format("2006-01-02T15:04:05.000000Z")
	}
	if f.Ip.IsPresent() {
		p.Ip = f.Ip.MustGet()
	}
	if f.Limit.IsPresent() {
		p.Limit = f.Limit.MustGet()
	}
	if f.Offset.IsPresent() {
		p.Offset = f.Offset.MustGet()
	}
	return p
}
