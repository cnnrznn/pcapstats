package main

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "os"
    "sort"
)

type pstat struct {
    count int
    bytes int
}

func (p pstat) incCount() pstat {
    p.count++
    return p
}

func (p pstat) incBytes(b int) pstat {
    p.bytes += b
    return p
}

func EndStat(packets []gopacket.Packet) {
    srcStat := make(map[gopacket.Endpoint]pstat)
    dstStat := make(map[gopacket.Endpoint]pstat)

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

    for _, k := range keys {
        fmt.Println(k, srcStat[k])
    }
}

func FlowStat(packets []gopacket.Packet) {
    flowStat := make(map[gopacket.Flow]pstat)

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

func main() {
    args := os.Args[1:]
    fn := args[0]

    if handle, err := pcap.OpenOffline(fn); err != nil {
        panic(err)
    } else {
        packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
        packets := []gopacket.Packet{}
        for packet := range packetSource.Packets() {
            packets = append(packets, packet)
        }

        FlowStat(packets)
        EndStat(packets)
    }
}

