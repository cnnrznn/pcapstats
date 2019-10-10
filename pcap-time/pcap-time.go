package main

import (
    "fmt"
    "github.com/cnnrznn/pcapstats"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "os"
    "time"
)

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

        buckets := pcapstats.TimeSlice(packets, time.Duration(10) * time.Millisecond)
        fmt.Println(buckets)

        //srcMap, dstMap := pcapstats.Endpoints(packets)
    }
}

