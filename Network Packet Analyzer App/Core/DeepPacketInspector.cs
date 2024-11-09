using System;
using System.Text;
using PacketDotNet;
using SharpPcap;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using SharpPcap.LibPcap;

public class DeepPacketInspector
{
    private readonly HashSet<string> suspiciousDomains = new HashSet<string> { "hypercustom.top", "piratesea" };
    private readonly HashSet<string> suspiciousIPs = new HashSet<string> { "192.168.1.100" };

    public event Action<string> PacketScanned;

    public void StartInspection(ICaptureDevice device)
    {
        device.OnPacketArrival += OnPacketArrival;
        device.Open(DeviceModes.Promiscuous);
        device.StartCapture();
    }

    public void AnalyzeFile(string filePath)
    {
        CaptureFileReaderDevice device = new CaptureFileReaderDevice(filePath);

        device.Open();
        device.OnPacketArrival += OnPacketArrival;
        device.Capture();
    }

    private void OnPacketArrival(object sender, PacketCapture pCap)
    {
        RawCapture rawPacket = pCap.GetPacket();

        if ((int)rawPacket.LinkLayerType == 119)
        {
            Console.WriteLine("Unsupported link layer 119 detected!");
            return;
        }

        Packet packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

        // Checking if the packet contains an IP packet
        if (packet.PayloadPacket is IPPacket ipPacket)
        {
            if (ipPacket.PayloadPacket is TcpPacket tcpPacket)
            {
                ProcessTcpPacket(ipPacket, tcpPacket);
            }
            else if (ipPacket.PayloadPacket is UdpPacket udpPacket)
            {
                ProcessUdpPacket(ipPacket, udpPacket);
            }
        }
    }

    private void ProcessTcpPacket(IPPacket ipPacket, TcpPacket tcpPacket)
    {
        if (!tcpPacket.HasPayloadData)
        {
            Console.WriteLine("No payload data found in TCP packet.");
            return;
        }

        string payload = Encoding.UTF8.GetString(tcpPacket.PayloadData);

        // Detecting Trickbot C2 communication on suspicious ports (e.g., port 443 for HTTPS)
        if (tcpPacket.DestinationPort == 443 || tcpPacket.SourcePort == 443)
        {
            if (IsSuspiciousPayload(payload) || IsSuspiciousIP(ipPacket.DestinationAddress.ToString()))
            {
                string message = "Potential malicious HTTPS traffic detected:\n";
                message += $"Source IP: {ipPacket.SourceAddress}, Destination IP: {ipPacket.DestinationAddress}\n\n";

                Console.WriteLine(message);

                PacketScanned?.Invoke(message);
            }
        }
    }

    private void ProcessUdpPacket(IPPacket ipPacket, UdpPacket udpPacket)
    {
        if (!udpPacket.HasPayloadData)
        {
            Console.WriteLine("No payload data found in UDP packet.");
            return;
        }

        string payload = Encoding.UTF8.GetString(udpPacket.PayloadData);

        // Checking for DNS requests to known Trickbot C2 domains
        if (udpPacket.DestinationPort == 53 || udpPacket.SourcePort == 53)
        {
            if (IsSuspiciousDomain(payload))
            {
                string message = "Suspicious DNS request detected:\n";
                message += $"Source IP: {ipPacket.SourceAddress}, Destination IP: {ipPacket.DestinationAddress}\n";
                message += $"Queried Domain: {payload}\n\n";

                Console.WriteLine(message);

                PacketScanned?.Invoke(message);
            }
        }
    }

    private bool IsSuspiciousDomain(string payload)
    {
        Console.WriteLine(payload);
        foreach (string domain in suspiciousDomains)
        {
            if (payload.Contains(domain))
            {
                return true;
            }
        }
        return false;
    }

    private bool IsSuspiciousIP(string ipAddress)
    {
        return suspiciousIPs.Contains(ipAddress);
    }

    private bool IsSuspiciousPayload(string payload)
    {
        // Heuristic: Checking for unusual payload patterns or sizes
        return payload.Length > 1000 || Regex.IsMatch(payload, @"[0-9a-f]{8,}|[a-zA-Z0-9+/=]{16,}");
    }
}
