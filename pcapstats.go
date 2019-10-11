package pcapstats

import (
    "fmt"
    "github.com/google/gopacket"
    "sort"
    "strings"
    "time"
)

type Stat struct {
    Count int
    Bytes int
}

type EndpointStatMap map[gopacket.Endpoint]Stat
type FlowStatMap map[gopacket.Flow]Stat

type EndpointMap map[gopacket.Endpoint]bool

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
    return fmt.Sprintf("%v, %v", s.Count, s.Bytes)
}

func (s Stat) incCount() Stat {
    s.Count++
    return s
}

func (s Stat) incBytes(b int) Stat {
    s.Bytes += b
    return s
}

func Keys(packets []gopacket.Packet) (keys []gopacket.Endpoint) {
    keys = make([]gopacket.Endpoint, 0)
    keyMap := make(map[gopacket.Endpoint]bool)

    for _, p := range packets {
        if net := p.NetworkLayer(); net != nil {
            netFlow := net.NetworkFlow()
            src, dst := netFlow.Endpoints()
            keyMap[src] = true
            keyMap[dst] = true
        }
    }

    // add all keys to keys
    for k, _ := range keyMap {
        keys = append(keys, k)
    }

    // sort the keys slice
    sort.Slice(keys, func(i, j int) bool { return keys[i].LessThan(keys[j]) })

    return
}

func Endpoints(packets []gopacket.Packet) (srcStat, dstStat EndpointStatMap) {
    srcStat = make(EndpointStatMap)
    dstStat = make(EndpointStatMap)

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

func Flow(packets []gopacket.Packet) (flowStat FlowStatMap) {
    flowStat = make(FlowStatMap)

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

func TimeSlice(packets []gopacket.Packet, millis time.Duration) (buckets [][]gopacket.Packet) {
    buckets = make([][]gopacket.Packet, 0)
    currBucket := make([]gopacket.Packet, 0)
    startTime := packets[0].Metadata().CaptureInfo.Timestamp

    for _, p := range packets {
        pTime := p.Metadata().CaptureInfo.Timestamp

        if pTime.Sub(startTime) > millis {
            buckets = append(buckets, currBucket)
            currBucket = make([]gopacket.Packet, 0)
            startTime = pTime
        }

        currBucket = append(currBucket, p)
    }
    buckets = append(buckets, currBucket)

    return
}

