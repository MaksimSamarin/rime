package trafficlogger

import (
 "os"
 "path/filepath"
 "testing"
)

func fleetTestServer() *trafficStatsServerImpl {
 return &trafficStatsServerImpl{StatsMap:make(map[string]*trafficStatsEntry),KickMap:make(map[string]struct{})}
}
func closeFleet(s *trafficStatsServerImpl){s.Fleet.file.Close();s.Fleet.lock.Close()}
func TestFleetRecoveryAndCompaction(t *testing.T){
 path:=filepath.Join(t.TempDir(),"usage.wal")
 s:=fleetTestServer();if err:=s.fleetOpen(path);err!=nil{t.Fatal(err)}
 if !s.LogTraffic("a",4096,512){t.Fatal("record failed")}
 ledger:=s.Fleet.ledger
 s.Fleet.size=8*1024*1024
 if !s.LogTraffic("a",10,20){t.Fatal("compaction failed")}
 closeFleet(s)
 s=fleetTestServer();if err:=s.fleetOpen(path);err!=nil{t.Fatal(err)};defer closeFleet(s)
 if s.StatsMap["a"].Tx!=4106||s.StatsMap["a"].Rx!=532||s.Fleet.ledger!=ledger{t.Fatal("recovery changed counters")}
}
func TestFleetPartialTailAndCorruption(t *testing.T){
 path:=filepath.Join(t.TempDir(),"usage.wal")
 s:=fleetTestServer();if err:=s.fleetOpen(path);err!=nil{t.Fatal(err)}
 if !s.LogTraffic("a",10,20){t.Fatal("record failed")};closeFleet(s)
 f,_:=os.OpenFile(path,os.O_APPEND|os.O_WRONLY,0600);f.Write([]byte{0,0,0});f.Close()
 s=fleetTestServer();if err:=s.fleetOpen(path);err!=nil{t.Fatal(err)}
 if s.StatsMap["a"].Tx!=10{t.Fatal("lost committed record")};closeFleet(s)
 f,_=os.OpenFile(path,os.O_RDWR,0600);f.WriteAt([]byte{255},12);f.Close()
 s=fleetTestServer();if err:=s.fleetOpen(path);err==nil{t.Fatal("corruption silently accepted")}
 if s.Fleet!=nil{closeFleet(s)}
}
func TestFleetDiskFailureDeniesTraffic(t *testing.T){
 s:=fleetTestServer();if err:=s.fleetOpen(filepath.Join(t.TempDir(),"usage.wal"));err!=nil{t.Fatal(err)}
 defer closeFleet(s)
 s.Fleet.file.Close()
 if s.LogTraffic("a",100,200)||!s.Fleet.failed{t.Fatal("traffic allowed after journal failure")}
 if s.StatsMap["a"]!=nil{t.Fatal("uncommitted counters published")}
}
func TestFleetExclusiveWriter(t *testing.T){
 path:=filepath.Join(t.TempDir(),"usage.wal")
 s:=fleetTestServer();if err:=s.fleetOpen(path);err!=nil{t.Fatal(err)};defer closeFleet(s)
 other:=fleetTestServer();if err:=other.fleetOpen(path);err==nil{closeFleet(other);t.Fatal("two writers allowed")}
}
