package main

import (
    "github.com/cnnrznn/pcapstats"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "os"
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

        pcapstats.FlowStat(packets)
        pcapstats.EndStat(packets)
    }
}

