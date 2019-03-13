package dns

import (
  "reflect"
  "sync"
)

// RRSet is a set of resource records indexed by name and type.
// RRSet is a secure type, preventing more than one operation from being made per time on top of a map type
type RRSet struct {
  l sync.Mutex
  m map[string]map[Type][]Record
  init bool
  
  onClear func( old map[string]map[Type][]Record )
  onSet func( old map[string]map[Type][]Record, new map[string]map[Type][]Record )
  onChange func( event Event, k string, old, new interface{} )
  onSetKey func( k string, old map[Type][]Record, new map[Type][]Record )
  onDeleteKey func( k string, old map[Type][]Record )
  onDeleteKeyInRecord func( k string, old map[Type][]Record, new map[Type][]Record )
  onAppendKeyInRecord func( k string, old map[Type][]Record, new map[Type][]Record )
  
  beforeOnClear func( old map[string]map[Type][]Record )
  beforeOnSet func( old map[string]map[Type][]Record, new map[string]map[Type][]Record )
  beforeOnChange func( event Event, k string, old, new interface{} )
  beforeOnSetKey func( k string, old map[Type][]Record, new map[Type][]Record )
  beforeOnDeleteKey func( k string, old map[Type][]Record )
  beforeOnDeleteKeyInRecord func( k string, old map[Type][]Record, new map[Type][]Record )
  beforeOnAppendKeyInRecord func( k string, old map[Type][]Record, new map[Type][]Record )
}

func(el *RRSet)SetBeforeOnClear( v func( map[string]map[Type][]Record ) ){
  el.beforeOnClear = v
}

func(el *RRSet)SetBeforeOnChange( v func( Event, string, interface{}, interface{} ) ){
  el.beforeOnChange = v
}

func(el *RRSet)SetBeforeOnSetKey( v func( string, map[Type][]Record, map[Type][]Record ) ){
  el.beforeOnSetKey = v
}

func(el *RRSet)SetBeforeDeleteKey( v func( string, map[Type][]Record ) ){
  el.beforeOnDeleteKey = v
}

func(el *RRSet)SetBeforeOnDeleteKeyInRecord( v func( string, map[Type][]Record, map[Type][]Record ) ){
  el.beforeOnDeleteKeyInRecord = v
}

func(el *RRSet)SetBeforeOnAppendKeyInRecord( v func( string, map[Type][]Record, map[Type][]Record ) ){
  el.beforeOnAppendKeyInRecord = v
}

func(el *RRSet)SetOnClear( v func( map[string]map[Type][]Record ) ){
  el.onClear = v
}

func(el *RRSet)SetOnChange( v func( Event, string, interface{}, interface{} ) ){
  el.onChange = v
}

func(el *RRSet)SetOnSetKey( v func( string, map[Type][]Record, map[Type][]Record ) ){
  el.onSetKey = v
}

func(el *RRSet)SetOnDeleteKey( v func( string, map[Type][]Record ) ){
  el.onDeleteKey = v
}

func(el *RRSet)SetOnDeleteKeyInRecord( v func( string, map[Type][]Record, map[Type][]Record ) ){
  el.onDeleteKeyInRecord = v
}

func(el *RRSet)SetOnAppendKeyInRecord( v func( string, map[Type][]Record, map[Type][]Record ) ){
  el.onAppendKeyInRecord = v
}

func(el *RRSet)deferOnClear( v map[string]map[Type][]Record ){
  if el.onClear != nil {
    el.onClear( v )
  }
}

func(el *RRSet)deferOnChange( event Event, k string, old interface{} ){
  if el.onChange != nil {
    el.onChange( event, k, old, el.m )
  }
}

func(el *RRSet)deferOnSet( old map[string]map[Type][]Record){
  if el.onSet != nil {
    el.onSet( old, el.m )
  }
}

func(el *RRSet)deferOnSetKey( k string, old map[Type][]Record ){
  if el.onSetKey != nil {
    el.onSetKey( k, old, el.m[k] )
  }
}

func(el *RRSet)deferDeleteKey( k string, old map[Type][]Record ){
  if el.onDeleteKey != nil {
    el.onDeleteKey( k, old )
  }
}

func(el *RRSet)deferOnDeleteKeyInRecord( k string, old map[Type][]Record ){
  if el.onDeleteKeyInRecord != nil {
    el.onDeleteKeyInRecord( k, old, el.m[k] )
  }
}

func(el *RRSet)deferOnAppendKeyInRecord( k string, old map[Type][]Record ){
  if el.onAppendKeyInRecord != nil {
    el.onAppendKeyInRecord( k, old, el.m[k] )
  }
}

// Clear RRSet
// Antes da função ser executada, a função beforeOnClear( oldRRSet ) é executada
// Depois da função ser executada, a função onClear( oldRRSet ) é executada
// Depois da função onClear() ser executada, a função onChange() é executada
// ok
func(el *RRSet)Clear(){
  el.l.Lock()
  
  if el.init == false {
    el.init = true
    el.m = make( map[string]map[Type][]Record )
  }
  
  old := el.m
  
  defer el.deferOnClear( old )
  defer el.deferOnChange(KEventClear, "", old)
  defer el.l.Unlock()
  
  if el.beforeOnClear != nil {
    el.beforeOnClear( el.m )
  }
  
  New := make( map[string]map[Type][]Record )
  
  if el.beforeOnChange != nil {
    el.beforeOnChange(KEventClear, "", old, New)
  }
  
  el.m = make( map[string]map[Type][]Record )
}

// Set new complete record
// Antes da função ser executada, a função beforeOnSet( oldRRSet, newRRSet ) é executada
// Depois da função ser executada, a função onSet( oldRRSet ) é executada
// Depois da função onSet() ser executada, a função onChange() é executada
// ok
func(el *RRSet)Set( v map[string]map[Type][]Record ){
  el.l.Lock()
  
  if el.init == false {
    el.init = true
    el.m = make( map[string]map[Type][]Record )
  }
  
  old := el.m
  
  defer el.deferOnSet( old )
  defer el.deferOnChange(KEventSet,"", old)
  defer el.l.Unlock()
  
  if el.beforeOnSet != nil {
    el.beforeOnSet( old, v )
  }
  
  if el.beforeOnChange != nil {
    el.beforeOnChange(KEventSet, "", old, v)
  }
  
  el.m = v
}

// Set a new record on given key
// ok
func(el *RRSet)SetKey( k string, v map[Type][]Record ){
  el.l.Lock()
  
  old := el.m[k]
  
  defer el.deferOnSetKey(k, old)
  defer el.deferOnChange(KEventSetKey, k, old)
  defer el.l.Unlock()
  
  if el.init == false {
    el.init = true
    el.m = make( map[string]map[Type][]Record )
  }
  
  if el.beforeOnSetKey != nil {
    el.beforeOnSetKey( k, old, v )
  }
  
  if el.beforeOnChange != nil {
    el.beforeOnChange(KEventClear, k, old, v)
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
  
  old := el.m[k]
  
  defer el.deferDeleteKey(k, old)
  defer el.deferOnChange(KEventDeleteKey, k, old)
  defer el.l.Unlock()
  
  if el.onDeleteKey != nil {
    el.onDeleteKey( k, old )
  }
  
  if el.beforeOnChange != nil {
    el.beforeOnChange(KEventClear, k, old, nil)
  }
  
  delete( el.m, k )
}

// Delete record inside a given key
func(el *RRSet)DeleteRecordInKey( k string, r Record ) {
  el.l.Lock()
  
  old := el.m[k]
  New := el.m[k]
  recordData := r.Get()
  
  defer el.deferOnDeleteKeyInRecord(k, old)
  defer el.deferOnChange(KEventDeleteKeyInRecord, k, old)
  defer el.l.Unlock()
  
  for rListType, rListValue := range old {
    if rListType == r.Type() {
      switch rListType {
      case TypeA:
        
        for i, v := range rListValue {
          listRecordData := v.Get()
          
          if recordData.(*A).A.Equal( listRecordData.(*A).A ) {
            New[TypeA] = append(New[TypeA][:i], New[TypeA][i+1:]...)
            return
          }
        }
      
      case TypeNS:
        
        for i, v := range rListValue {
          listRecordData := v.Get()
          
          if recordData.(*NS).NS == listRecordData.(*NS).NS {
            New[TypeNS] = append(New[TypeNS][:i], New[TypeNS][i+1:]...)
            return
          }
        }
      
      case TypeCNAME:
        
        for i, v := range rListValue {
          listRecordData := v.Get()
          
          if recordData.(*CNAME).CNAME == listRecordData.(*CNAME).CNAME {
            New[TypeCNAME] = append(New[TypeCNAME][:i], New[TypeCNAME][i+1:]...)
            return
          }
        }
      
      case TypeSOA:
        
        for i, v := range rListValue {
          listRecordData := v.Get()
          
          if recordData.(*SOA).Serial == listRecordData.(*SOA).Serial {
            New[TypeSOA] = append(New[TypeSOA][:i], New[TypeSOA][i+1:]...)
            return
          }
        }
      
      case TypePTR:
        
        for i, v := range rListValue {
          listRecordData := v.Get()
          
          if recordData.(*PTR).PTR == listRecordData.(*PTR).PTR {
            New[TypePTR] = append(New[TypePTR][:i], New[TypePTR][i+1:]...)
            return
          }
        }
      
      case TypeMX:
        
        for i, v := range rListValue {
          listRecordData := v.Get()
          
          if recordData.(*MX).MX == listRecordData.(*MX).MX {
            New[TypeMX] = append(New[TypeMX][:i], New[TypeMX][i+1:]...)
            return
          }
        }
      
      case TypeTXT:
        
        for i, v := range rListValue {
          listRecordData := v.Get()
          
          if reflect.DeepEqual(recordData.(*TXT).TXT, listRecordData.(*TXT).TXT) {
            New[TypeTXT] = append(New[TypeTXT][:i], New[TypeTXT][i+1:]...)
            return
          }
        }
      
      case TypeAAAA:
        
        for i, v := range rListValue {
          listRecordData := v.Get()
          
          if recordData.(*AAAA).AAAA.Equal( listRecordData.(*AAAA).AAAA ) {
            New[TypeAAAA] = append(New[TypeAAAA][:i], New[TypeAAAA][i+1:]...)
            return
          }
        }
      
      case TypeSRV:
        
        for i, v := range rListValue {
          listRecordData := v.Get()
          
          if recordData.(*SRV).Target == listRecordData.(*SRV).Target {
            New[TypeSRV] = append(New[TypeSRV][:i], New[TypeSRV][i+1:]...)
            return
          }
        }
      
      case TypeDNAME:
        
        for i, v := range rListValue {
          listRecordData := v.Get()
          
          if recordData.(*DNAME).DNAME == listRecordData.(*DNAME).DNAME {
            New[TypeDNAME] = append(New[TypeDNAME][:i], New[TypeDNAME][i+1:]...)
            return
          }
        }
      
      case TypeOPT:
        
        for i, v := range rListValue {
          listRecordData := v.Get()
          
          if reflect.DeepEqual(recordData.(*OPT).Options, listRecordData.(*OPT).Options) {
            New[TypeOPT] = append(New[TypeOPT][:i], New[TypeOPT][i+1:]...)
            return
          }
        }
      
      case TypeCAA:
        
        for i, v := range rListValue {
          listRecordData := v.Get()
          
          if recordData.(*CAA).Value == listRecordData.(*CAA).Value && recordData.(*CAA).Tag == listRecordData.(*CAA).Tag {
            New[TypeCAA] = append(New[TypeCAA][:i], New[TypeCAA][i+1:]...)
            return
          }
        }
      }
    }
  }
  
  if el.beforeOnDeleteKeyInRecord != nil {
    el.beforeOnDeleteKeyInRecord(k, old, New)
  }
  
  if el.beforeOnChange != nil {
    el.beforeOnChange(KEventClear, k, old, New)
  }
  
  el.m[k] = New
}

func(el *RRSet)AppendRecordInKey( k string, r Record ) {
  el.l.Lock()
  
  if el.init == false {
    el.init = true
    el.m = make( map[string]map[Type][]Record )
  }
  
  old := el.m[k]
  New := el.m[k]
  
  defer el.deferOnAppendKeyInRecord(k, old)
  defer el.deferOnChange(KEventAppendKeyInRecord, k, old)
  defer el.l.Unlock()
  
  rType := r.Type()
  if len(New[rType]) == 0 {
    New = map[Type][]Record{ rType: { r } }
  } else {
    New[rType] = append( New[rType], r )
  }
  
  if el.beforeOnAppendKeyInRecord != nil {
    el.beforeOnAppendKeyInRecord(k, old, New)
  }
  
  if el.beforeOnChange != nil {
    el.beforeOnChange(KEventClear, k, old, New)
  }
  
  el.m[k] = New
}


// Get all records
func(el *RRSet)GetAll() map[string]map[Type][]Record {
  el.l.Lock()
  defer el.l.Unlock()
  
  return el.m
}
