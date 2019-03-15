package dns

type Event int

var Events = [...]string{
	"",
	"clear",
	"set",
	"setKey",
	"deleteKey",
	"deleteKeyInRecord",
	"appendKeyInRecord",
}

func (el Event) String() string {
	return Events[el]
}

const (
	KEventClear Event = iota + 1
	KEventSet
	KEventSetKey
	KEventDeleteKey
	KEventDeleteKeyInRecord
	KEventAppendKeyInRecord
)
