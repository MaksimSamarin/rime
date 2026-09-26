// Fleet extension to Hysteria 2.12.3. Records accepted payload before forwarding.
package trafficlogger

import (
 "crypto/rand"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "hash/crc32"
 "io"
 "net/http"
 "os"
 "path/filepath"
 "syscall"
)

type fleetRecord struct {
 Kind string `json:"kind"`
 Ledger string `json:"ledger,omitempty"`
 Seq uint64 `json:"seq"`
 ID string `json:"id,omitempty"`
 Tx uint64 `json:"tx,omitempty"`
 Rx uint64 `json:"rx,omitempty"`
 Totals map[string]*trafficStatsEntry `json:"totals,omitempty"`
}

type fleetJournal struct {
 file *os.File
 lock *os.File
 path string
 ledger string
 seq uint64
 failed bool
 size int64
}

func fleetFrame(w io.Writer, record fleetRecord) (int64,error) {
 data,err:=json.Marshal(record);if err!=nil{return 0,err}
 if len(data)>16*1024*1024{return 0,errors.New("fleet journal frame too large")}
 var header [8]byte
 binary.BigEndian.PutUint32(header[:4],uint32(len(data)))
 binary.BigEndian.PutUint32(header[4:],crc32.ChecksumIEEE(data))
 if n,err:=w.Write(header[:]);err!=nil{return 0,err}else if n!=len(header){return 0,io.ErrShortWrite}
 if n,err:=w.Write(data);err!=nil{return 0,err}else if n!=len(data){return 0,io.ErrShortWrite}
 return int64(len(data)+8),nil
}

func (s *trafficStatsServerImpl) fleetOpen(path string) error {
 if path=="" {return nil}
 lock,err:=os.OpenFile(path+".lock",os.O_CREATE|os.O_RDWR,0600);if err!=nil{return err}
 if err=syscall.Flock(int(lock.Fd()),syscall.LOCK_EX|syscall.LOCK_NB);err!=nil{lock.Close();return err}
 f,err:=os.OpenFile(path,os.O_CREATE|os.O_RDWR,0600);if err!=nil{lock.Close();return err}
 j:=&fleetJournal{file:f,lock:lock,path:path};s.Fleet=j
 var offset int64
 for {
  var h [8]byte
  _,err=io.ReadFull(f,h[:])
  if err==io.EOF{break}
  if err==io.ErrUnexpectedEOF{if err=f.Truncate(offset);err!=nil{return err};break}
  if err!=nil{return err}
  size:=binary.BigEndian.Uint32(h[:4]);if size==0||size>16*1024*1024{return errors.New("invalid fleet journal frame size")}
  data:=make([]byte,size)
  if _,err=io.ReadFull(f,data);err==io.EOF||err==io.ErrUnexpectedEOF{if err=f.Truncate(offset);err!=nil{return err};break}else if err!=nil{return err}
  if crc32.ChecksumIEEE(data)!=binary.BigEndian.Uint32(h[4:]){return errors.New("fleet journal checksum mismatch")}
  var r fleetRecord;if err=json.Unmarshal(data,&r);err!=nil{return err}
  if offset==0 {
   if r.Kind!="snapshot"||len(r.Ledger)!=32{return errors.New("invalid fleet journal header")}
   j.ledger=r.Ledger;j.seq=r.Seq
   if r.Totals!=nil{s.StatsMap=r.Totals}
  }else{
   if r.Kind!="delta"||r.Seq!=j.seq+1||r.ID==""{return errors.New("invalid fleet journal sequence")}
   e:=s.StatsMap[r.ID];if e==nil{e=&trafficStatsEntry{};s.StatsMap[r.ID]=e}
   if ^uint64(0)-e.Tx<r.Tx||^uint64(0)-e.Rx<r.Rx{return errors.New("fleet counter overflow")}
   e.Tx+=r.Tx;e.Rx+=r.Rx;j.seq=r.Seq
  }
  offset+=int64(size)+8
 }
 if _,err=f.Seek(0,io.SeekEnd);err!=nil{return err}
 if offset==0 {
  random:=make([]byte,16);if _,err=rand.Read(random);err!=nil{return err};j.ledger=hex.EncodeToString(random)
  if offset,err=fleetFrame(f,fleetRecord{Kind:"snapshot",Ledger:j.ledger,Totals:s.StatsMap});err!=nil{return err}
 }
 if err=f.Sync();err!=nil{return err}
 dir,err:=os.Open(filepath.Dir(path));if err!=nil{return err};err=dir.Sync();dir.Close();if err!=nil{return err}
 if _,err=f.Seek(0,io.SeekEnd);err!=nil{return err};j.size=offset
 return nil
}

func (s *trafficStatsServerImpl) fleetCompact() error {
 j:=s.Fleet
 f,err:=os.OpenFile(j.path+".next",os.O_CREATE|os.O_TRUNC|os.O_WRONLY,0600);if err!=nil{return err}
 size,err:=fleetFrame(f,fleetRecord{Kind:"snapshot",Ledger:j.ledger,Seq:j.seq,Totals:s.StatsMap})
 if err==nil{err=f.Sync()};closeErr:=f.Close();if err!=nil{return err};if closeErr!=nil{return closeErr}
 if err=os.Rename(j.path+".next",j.path);err!=nil{return err}
 dir,err:=os.Open(filepath.Dir(j.path));if err!=nil{return err};err=dir.Sync();dir.Close();if err!=nil{return err}
 j.file.Close()
 j.file,err=os.OpenFile(j.path,os.O_RDWR|os.O_APPEND,0600);if err!=nil{return err}
 j.size=size;return nil
}

func (s *trafficStatsServerImpl) fleetAppend(id string,tx,rx uint64) bool {
 j:=s.Fleet;if j==nil{return true};if j.failed{return false}
 if j.size>=8*1024*1024{if err:=s.fleetCompact();err!=nil{j.failed=true;return false}}
 e:=s.StatsMap[id]
 if e!=nil && (^uint64(0)-e.Tx<tx||^uint64(0)-e.Rx<rx){j.failed=true;return false}
 n,err:=fleetFrame(j.file,fleetRecord{Kind:"delta",Seq:j.seq+1,ID:id,Tx:tx,Rx:rx})
 if err==nil{err=j.file.Sync()}
 if err!=nil{j.failed=true;return false}
 j.seq++;j.size+=n;return true
}

// FleetRegisterConnection is called by the patched core immediately after auth.
// Callbacks are copied under lock and invoked outside it to avoid deadlocks.
func (s *trafficStatsServerImpl) FleetRegisterConnection(id,key string,close func()) {
 s.Mutex.Lock();defer s.Mutex.Unlock()
 if s.FleetConnections[id]==nil{s.FleetConnections[id]=make(map[string]func())}
 s.FleetConnections[id][key]=close
}
func (s *trafficStatsServerImpl) FleetUnregisterConnection(id,key string) {
 s.Mutex.Lock();defer s.Mutex.Unlock()
 delete(s.FleetConnections[id],key);if len(s.FleetConnections[id])==0{delete(s.FleetConnections,id)}
}
func (s *trafficStatsServerImpl) fleetKick(w http.ResponseWriter,r *http.Request) {
 var ids []string
 if err:=json.NewDecoder(http.MaxBytesReader(w,r.Body,1024*1024)).Decode(&ids);err!=nil{http.Error(w,"invalid ids",400);return}
 callbacks:=[]func(){}
 s.Mutex.Lock()
 for _,id:=range ids{for _,close:=range s.FleetConnections[id]{callbacks=append(callbacks,close)}}
 s.Mutex.Unlock()
 for _,close:=range callbacks{close()}
 w.Header().Set("Content-Type","application/json")
 fmt.Fprintf(w,"{\"closed\":%d}",len(callbacks))
}
func (s *trafficStatsServerImpl) fleetSnapshot(w http.ResponseWriter,r *http.Request) {
 s.Mutex.RLock();defer s.Mutex.RUnlock()
 if s.Fleet==nil{http.Error(w,"durable ledger is not configured",503);return}
 if s.Fleet.failed{http.Error(w,"durable ledger failed",503);return}
 w.Header().Set("Content-Type","application/json")
 json.NewEncoder(w).Encode(map[string]any{"ledger":s.Fleet.ledger,"seq":s.Fleet.seq,"totals":s.StatsMap,"durable":true})
}
