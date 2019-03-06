package dns

import (
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
  
  /*for recordKey := range el.m[ k ]{
  
  }*/
}

// Get all records
func(el *RRSet)GetAll() map[string]map[Type][]Record {
  el.l.Lock()
  defer el.l.Unlock()
  
  return el.m
}
