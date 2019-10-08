package pcapstats

import (
    "fmt"
    "github.com/google/gopacket"
    "sort"
    "strings"
)

type Stat struct {
    count int
    bytes int
}

type EndpointStatMap map[gopacket.Endpoint]Stat

func (em EndpointStatMap) String() string {
    var sb strings.Builder
    keys := make([]gopacket.Endpoint, 0)
    for k := range em {
        keys = append(keys, k)
    }
    sort.Slice(keys, func(i, j int) bool { return keys[i].LessThan(keys[j]) })

    for _, k := range keys {
        fmt.Fprintf(&sb, "%v, %v\n", k, em[k])
    }

    return sb.String()
}

func (s Stat) String() string {
    return fmt.Sprintf("%v, %v", s.count, s.bytes)
}

func (s Stat) incCount() Stat {
    s.count++
    return s
}

func (s Stat) incBytes(b int) Stat {
    s.bytes += b
    return s
}

func Endpoints(packets []gopacket.Packet) (srcStat, dstStat EndpointStatMap) {
    srcStat = make(map[gopacket.Endpoint]Stat)
    dstStat = make(map[gopacket.Endpoint]Stat)

    for _, packet := range packets {
        if net := packet.NetworkLayer(); net != nil {
            netFlow := net.NetworkFlow()
            src, dst := netFlow.Endpoints()
            size := packet.Metadata().CaptureInfo.Length

            srcStat[src] = srcStat[src].incCount()
            srcStat[src] = srcStat[src].incBytes(size)
            dstStat[dst] = dstStat[dst].incCount()
            dstStat[dst] = dstStat[dst].incBytes(size)
        }
    }

    return
}

func Flow(packets []gopacket.Packet) (flowStat map[gopacket.Flow]Stat) {
    flowStat = make(map[gopacket.Flow]Stat)

    for _, packet := range packets {
        if net := packet.NetworkLayer(); net != nil {
            netFlow := net.NetworkFlow()
            size := packet.Metadata().CaptureInfo.Length

            //fmt.Println(src, dst, size)

            flowStat[netFlow] = flowStat[netFlow].incCount()
            flowStat[netFlow] = flowStat[netFlow].incBytes(size)
        }
    }

    return
}

