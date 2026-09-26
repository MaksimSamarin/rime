"""Apply bounded, version-checked source changes to a separate Hysteria tree."""
from pathlib import Path
import shutil
import sys

root=Path(sys.argv[1]).resolve()
patch=Path(__file__).resolve().parent
http=root/'extras/trafficlogger/http.go'
text=http.read_text()
def replace(source,old,new):
    if source.count(old)!=1:raise RuntimeError('Upstream source anchor mismatch: '+old[:70])
    return source.replace(old,new,1)
text=replace(text,'"net/http"','"net/http"\n "os"')
text=replace(text,'return &trafficStatsServerImpl{','s := &trafficStatsServerImpl{')
text=replace(text,'Secret:    secret,','Secret:    secret,\n FleetConnections: make(map[string]map[string]func()),')
text=replace(text,'\n}\n\ntype trafficStatsServerImpl struct','\n if err := s.fleetOpen(os.Getenv("FLEET_TRAFFIC_WAL")); err != nil { panic(err) }; return s\n}\n\ntype trafficStatsServerImpl struct')
text=replace(text,'Secret    string','Secret    string\n Fleet *fleetJournal\n FleetConnections map[string]map[string]func()')
text=replace(text,'entry, ok := s.StatsMap[id]','if !s.fleetAppend(id,tx,rx) { return false }\n entry, ok := s.StatsMap[id]')
text=replace(text,'if r.Method == http.MethodGet && r.URL.Path == "/" {','if r.Method == http.MethodGet && r.URL.Path == "/fleet/snapshot" { s.fleetSnapshot(w,r); return }\n if r.Method == http.MethodPost && r.URL.Path == "/fleet/kick" { s.fleetKick(w,r); return }\n if r.Method == http.MethodGet && r.URL.Path == "/" {')
text=replace(text,'bClear, _ := strconv.ParseBool(r.URL.Query().Get("clear"))','bClear, _ := strconv.ParseBool(r.URL.Query().Get("clear"))\n if bClear && s.Fleet != nil { http.Error(w,"cannot clear a durable ledger",409); return }')
http.write_text(text)
shutil.copyfile(patch/'durable.go',http.parent/'fleet_durable.go')
server=root/'core/server/server.go'
text=server.read_text()
text=replace(text,'tl.LogOnlineState(handler.authID, false)','tl.LogOnlineState(handler.authID, false)\n if registry,ok := tl.(interface{FleetUnregisterConnection(string,string)}); ok { registry.FleetUnregisterConnection(handler.authID, fmt.Sprintf("%p",conn)) }')
text=replace(text,'"errors"','"errors"\n "fmt"')
text=replace(text,'tl.LogOnlineState(id, true)','tl.LogOnlineState(id, true)\n if registry,ok := tl.(interface{FleetRegisterConnection(string,string,func())}); ok { registry.FleetRegisterConnection(id,fmt.Sprintf("%p",h.conn),func(){ _ = h.conn.CloseWithError(closeErrCodeTrafficLimitReached, "") }) }')
# Sniffed/putback payload must take the same durable accounting path.
text=replace(text,'n, _ := tConn.Write(putback)','if trafficLogger != nil && !trafficLogger.LogTraffic(h.authID,uint64(len(putback)),0) { _ = stream.Close(); _ = tConn.Close(); return }\n n, _ := tConn.Write(putback)')
server.write_text(text)
print('Patched durable accounting, snapshot API and connection registry in isolated source tree')
