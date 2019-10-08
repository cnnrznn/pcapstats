package pcapstats

import (
    "fmt"
    "github.com/google/gopacket"
    "sort"
)

type Stat struct {
    count int
    bytes int
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

func EndStat(packets []gopacket.Packet) {
    srcStat := make(map[gopacket.Endpoint]Stat)
    dstStat := make(map[gopacket.Endpoint]Stat)

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

    keys := make([]gopacket.Endpoint, 0)
    for k := range srcStat {
        keys = append(keys, k)
    }
    sort.Slice(keys, func(i, j int) bool { return keys[i].LessThan(keys[j]) })

    fmt.Println("IP, srcCount, srcBytes, dstCount, dstBytes")
    for _, k := range keys {
        fmt.Printf("%v, %v, %v\n", k, srcStat[k], dstStat[k])
    }
}

func FlowStat(packets []gopacket.Packet) {
    flowStat := make(map[gopacket.Flow]Stat)

    for _, packet := range packets {
        if net := packet.NetworkLayer(); net != nil {
            netFlow := net.NetworkFlow()
            size := packet.Metadata().CaptureInfo.Length

            //fmt.Println(src, dst, size)

            flowStat[netFlow] = flowStat[netFlow].incCount()
            flowStat[netFlow] = flowStat[netFlow].incBytes(size)
        } else {
            //fmt.Println(packet)
            // It's an ARP packet
        }
    }
}

