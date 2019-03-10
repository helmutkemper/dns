package dns

import (
  "fmt"
  "reflect"
  "sync"
)

// RRSet is a set of resource records indexed by name and type.
// RRSet is a secure type, preventing more than one operation from being made per time on top of a map type
type RRSet struct {
  l sync.Mutex
  m map[string]map[Type][]Record
  init bool
}

// Clear RRSet
func(el *RRSet)Clear(){
  el.l.Lock()
  defer el.l.Unlock()
  
  el.init = true
  el.m = make( map[string]map[Type][]Record )
}

// Set a new record
func(el *RRSet)Set( k string, v map[Type][]Record ){
  el.l.Lock()
  defer el.l.Unlock()
  
  if el.init == false {
    el.init = true
    el.m = make( map[string]map[Type][]Record )
  }
  
  el.m[ k ] = v
}

// Get length
func(el *RRSet)Len() int {
  el.l.Lock()
  defer el.l.Unlock()
  
  return len( el.m )
}

// Get record by given key
func(el *RRSet)GetKey( k string ) (map[Type][]Record, bool) {
  el.l.Lock()
  defer el.l.Unlock()
  
  r, ok := el.m[ k ]
  
  return r, ok
}

// Delete record by given key
func(el *RRSet)DeleteKey( k string ) {
  el.l.Lock()
  defer el.l.Unlock()
  
  delete( el.m, k )
}

// Delete record inside a given key
func(el *RRSet)DeleteRecordInKey( k string, r Record ) {
  el.l.Lock()
  defer el.l.Unlock()
  
  recordList := el.m[k]
  recordData := r.Get()
  
  for rListType, rListValue := range recordList {
    if rListType == r.Type() {
      switch rListType {
      case TypeA:
  
        for i, v := range rListValue {
          listRecordData := v.Get()
    
          if recordData.(*A).A.Equal( listRecordData.(*A).A ) {
            el.m[k][TypeA] = append(el.m[k][TypeA][:i], el.m[k][TypeA][i+1:]...)
            return
          }
        }
        
      case TypeNS:
  
        for i, v := range rListValue {
          listRecordData := v.Get()
    
          if recordData.(*NS).NS == listRecordData.(*NS).NS {
            el.m[k][TypeNS] = append(el.m[k][TypeNS][:i], el.m[k][TypeNS][i+1:]...)
            return
          }
        }
        
      case TypeCNAME:
  
        for i, v := range rListValue {
          listRecordData := v.Get()
    
          if recordData.(*CNAME).CNAME == listRecordData.(*CNAME).CNAME {
            el.m[k][TypeCNAME] = append(el.m[k][TypeCNAME][:i], el.m[k][TypeCNAME][i+1:]...)
            return
          }
        }
        
      case TypeSOA:
  
        for i, v := range rListValue {
          listRecordData := v.Get()
    
          if recordData.(*SOA).Serial == listRecordData.(*SOA).Serial {
            el.m[k][TypeSOA] = append(el.m[k][TypeSOA][:i], el.m[k][TypeSOA][i+1:]...)
            return
          }
        }
        
      case TypePTR:
  
        for i, v := range rListValue {
          listRecordData := v.Get()
    
          if recordData.(*PTR).PTR == listRecordData.(*PTR).PTR {
            el.m[k][TypePTR] = append(el.m[k][TypePTR][:i], el.m[k][TypePTR][i+1:]...)
            return
          }
        }
        
      case TypeMX:
  
        for i, v := range rListValue {
          listRecordData := v.Get()
    
          if recordData.(*MX).MX == listRecordData.(*MX).MX {
            el.m[k][TypeMX] = append(el.m[k][TypeMX][:i], el.m[k][TypeMX][i+1:]...)
            return
          }
        }
        
      case TypeTXT:
  
        for i, v := range rListValue {
          listRecordData := v.Get()
    
          if reflect.DeepEqual(recordData.(*TXT).TXT, listRecordData.(*TXT).TXT) {
            el.m[k][TypeTXT] = append(el.m[k][TypeTXT][:i], el.m[k][TypeTXT][i+1:]...)
            return
          }
        }
        
      case TypeAAAA:
  
        for i, v := range rListValue {
          listRecordData := v.Get()
    
          if recordData.(*AAAA).AAAA.Equal( listRecordData.(*AAAA).AAAA ) {
            el.m[k][TypeAAAA] = append(el.m[k][TypeAAAA][:i], el.m[k][TypeAAAA][i+1:]...)
            return
          }
        }
        
      case TypeSRV:
    
        for i, v := range rListValue {
          listRecordData := v.Get()
      
          if recordData.(*SRV).Target == listRecordData.(*SRV).Target {
            el.m[k][TypeSRV] = append(el.m[k][TypeSRV][:i], el.m[k][TypeSRV][i+1:]...)
            return
          }
        }
  
      case TypeDNAME:
  
        for i, v := range rListValue {
          listRecordData := v.Get()
    
          if recordData.(*DNAME).DNAME == listRecordData.(*DNAME).DNAME {
            el.m[k][TypeDNAME] = append(el.m[k][TypeDNAME][:i], el.m[k][TypeDNAME][i+1:]...)
            return
          }
        }
        
      case TypeOPT:
  
        for i, v := range rListValue {
          listRecordData := v.Get()
    
          if reflect.DeepEqual(recordData.(*OPT).Options, listRecordData.(*OPT).Options) {
            el.m[k][TypeOPT] = append(el.m[k][TypeOPT][:i], el.m[k][TypeOPT][i+1:]...)
            return
          }
        }
        
      case TypeCAA:
  
        for i, v := range rListValue {
          listRecordData := v.Get()
    
          if recordData.(*CAA).Value == listRecordData.(*CAA).Value && recordData.(*CAA).Tag == listRecordData.(*CAA).Tag {
            el.m[k][TypeCAA] = append(el.m[k][TypeCAA][:i], el.m[k][TypeCAA][i+1:]...)
            return
          }
        }
        
      }
    }
  }
}

func(el *RRSet)AppendRecordInKey( k string, r Record ) {
  el.l.Lock()
  defer el.l.Unlock()
  
  if len(el.m) == 0 {
    el.init = true
    el.m = make( map[string]map[Type][]Record )
  }
  
  rType := r.Type()
  if len(el.m[k][rType]) == 0 {
    el.m[k] = map[Type][]Record{ rType: { r } }
    return
  }
  
  el.m[k][rType] = append( el.m[k][rType], r )
  fmt.Printf("%v\n", el.m)
}


// Get all records
func(el *RRSet)GetAll() map[string]map[Type][]Record {
  el.l.Lock()
  defer el.l.Unlock()
  
  return el.m
}
