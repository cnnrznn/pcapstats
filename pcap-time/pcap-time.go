package main

import (
    "fmt"
    "github.com/cnnrznn/pcapstats"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "os"
    "time"
)

func toStringSlice(s []gopacket.Endpoint) (strSlice []string) {
    strSlice = make([]string, len(s))

    for i, v := range s {
        strSlice[i] = v.String()
    }

    return
}

func handlePackets(packets []gopacket.Packet) {
    buckets := pcapstats.TimeSlice(packets, time.Duration(10) * time.Millisecond)
    endpoints := pcapstats.Keys(packets)
    strEndpoints := toStringSlice(endpoints)
    strTypes := []string{"Send", "Recv"}
    strValues := []string{"Count", "Bytes"}

    for i:=0; i<len(strEndpoints); i++ {
        for j:=0; j<len(strTypes); j++ {
            for k:=0; k<len(strValues); k++ {
                fmt.Printf("%v-%v-%v, ", strEndpoints[i],
                                         strTypes[j],
                                         strValues[k])
            }
        }
    }
    fmt.Println()

    for _, b := range buckets {
        srcMap, dstMap := pcapstats.Endpoints(b)
        for _, e := range endpoints {
            fmt.Printf("%v, %v, %v, %v, ",
                                   srcMap[e].Count,
                                   srcMap[e].Bytes,
                                   dstMap[e].Count,
                                   dstMap[e].Bytes)
        }
        fmt.Println()
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

        handlePackets(packets)
    }
}

