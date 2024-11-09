using Network_Packet_Analyzer_App.MVVM.Model;
using Newtonsoft.Json.Linq;
using PacketDotNet;
using SharpPcap.LibPcap;
using SharpPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Policy;
using System.Net.Sockets;

namespace Network_Packet_Analyzer_App.Core
{
    internal class OnlinePacketDetective
    {
        private DNSTunnelingDetective dnsTDetective;
        private HTTPSTunnelingDetective httpsTDetective;
        private SSHTunnelingDetective sshTDetective;

        private readonly Regex urlRegex = new Regex(@"https?://[^\s<>""']+", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public OnlinePacketDetective()
        {
            dnsTDetective = new DNSTunnelingDetective();
            httpsTDetective = new HTTPSTunnelingDetective();
        }

        public void AnalyzeDNSPacket(Packet packet, ref PacketInfo packetInfo)
        {
            try
            {
                DNSQuery dnsQuery = ExtractDnsQuery(packet);

                packetInfo.DNSQueryInfo = AnalyzeDNSQueryLive(dnsQuery);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error analyzing live packet: {ex.Message}");
            }
        }

        public void AnalyzeHTTPPacket(IPPacket ipPacket, ref PacketInfo packetInfo)
        {
            HTTPSession httpSession = ExtractHTTPSession(ipPacket);
            // Console.WriteLine("Extracted http session: " + httpSession + "\n");

            if (httpSession != null)
            {
                packetInfo.HTTPSInfo = httpsTDetective.AnalyzeSession(httpSession);
            }
        }

        public void AnalyzeSSHPacket(Packet packet, ref PacketInfo packetInfo)
        {
            packetInfo.SSHInfo = sshTDetective.AnalyzeSession(packet);

            // Console.WriteLine($"SSH Packet analyzed: {packetInfo}");
        }

        /*private string ExtractUrls(Packet packet)
        {
            var payload = ExtractPayload(packet);
            if (payload != null && payload.Length > 0)
            {
                try
                {
                    // Try to decode as ASCII first
                    string payloadText = Encoding.ASCII.GetString(payload);
                    foreach (Match match in urlRegex.Matches(payloadText))
                    {
                        return match.Value;
                    }

                    // Try UTF-8 if ASCII didn't find anything
                    if (!urlRegex.IsMatch(payloadText))
                    {
                        payloadText = Encoding.UTF8.GetString(payload);
                        foreach (Match match in urlRegex.Matches(payloadText))
                        {
                            return match.Value;
                        }
                    }
                }
                catch
                {
                    // Ignore encoding errors
                }
            }

            return "google.com";
        }*/

        private DNSQuery ExtractDnsQuery(Packet packet)
        {
            // Checking if the packet is an IP packet
            if (packet.PayloadPacket is IPPacket ipPacket)
            {
                // Checking if the payload is a UDP packet
                if (ipPacket.PayloadPacket is UdpPacket udpPacket)
                {
                    // Checking if it's a DNS packet (typically on port 53)
                    if (udpPacket.DestinationPort == 53 || udpPacket.SourcePort == 53)
                    {
                        var dnsPayload = ExtractPayload(packet);
                        if (dnsPayload != null && dnsPayload.Length >= 12) // DNS header is at least 12 bytes
                        {
                            try
                            {
                                DNSQuery dnsQuery = new DNSQuery
                                {
                                    // Extracting Transaction ID (first 2 bytes)
                                    TransactionID = BitConverter.ToUInt16(new byte[] { dnsPayload[1], dnsPayload[0] }, 0),

                                    // Getting the source IP
                                    SourceIP = ipPacket.SourceAddress.ToString(),

                                    // Setting the timestamp
                                    Timestamp = DateTime.UtcNow,

                                    // Getting the query flags from bytes 2-3
                                    RecursionDesired = (dnsPayload[2] & 0x01) == 1,
                                    IsTruncated = (dnsPayload[2] & 0x02) == 2,

                                    // Getting the query length
                                    QueryLength = dnsPayload.Length,

                                    // Parsing the domain name
                                    QueryDomain = ParseDomainName(dnsPayload, 12, out int offset),

                                    // Getting the query type (bytes after domain name)
                                    QueryType = (QueryType)BitConverter.ToUInt16(new byte[] { dnsPayload[offset + 1], dnsPayload[offset] }, 0),

                                    // Getting the query class
                                    QueryClass = BitConverter.ToUInt16(new byte[] { dnsPayload[offset + 3], dnsPayload[offset + 2] }, 0),

                                    // Storing the packet
                                    PacketData = packet
                                };

                                // Processing domain parts
                                string[] domainParts = dnsQuery.QueryDomain.Split('.');
                                if (domainParts.Length >= 2)
                                {
                                    // Getting the last two parts for root domain
                                    dnsQuery.RootDomain = domainParts[domainParts.Length - 2] + "." + domainParts[domainParts.Length - 1];
                                    // Getting all parts except the last two for subdomains
                                    dnsQuery.Subdomains = domainParts.Take(domainParts.Length - 2).ToList();
                                }
                                else
                                {
                                    dnsQuery.RootDomain = dnsQuery.QueryDomain;
                                    dnsQuery.Subdomains = new List<string>();
                                }

                                // Parsing answers if response packet
                                if (udpPacket.SourcePort == 53)
                                {
                                    dnsQuery.Answers = ParseDNSAnswers(dnsPayload, offset + 4);
                                    dnsQuery.ResponseLength = dnsPayload.Length;
                                }

                                return dnsQuery;
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"Error processing DNS packet: {ex.Message}");
                            }
                        }
                    }
                }
            }

            return null;
        }

        // Helper method to parse domain names from DNS packet
        private string ParseDomainName(byte[] data, int offset, out int endOffset)
        {
            List<string> domainParts = new List<string>();
            int currentOffset = offset;
            int length = 0;

            while (currentOffset < data.Length && (length = data[currentOffset]) > 0)
            {
                if ((length & 0xC0) == 0xC0)
                {
                    // Handling compression
                    int pointerOffset = ((length & 0x3F) << 8) | data[currentOffset + 1];
                    if (pointerOffset < data.Length)
                    {
                        int tempOffset;
                        domainParts.Add(ParseDomainName(data, pointerOffset, out tempOffset));
                    }
                    currentOffset += 2;
                    break;
                }

                if (currentOffset + length + 1 > data.Length)
                    break;

                string label = Encoding.ASCII.GetString(data, currentOffset + 1, length);
                domainParts.Add(label);
                currentOffset += length + 1;
            }

            endOffset = currentOffset;
            return string.Join(".", domainParts);
        }

        // Helper method to parse DNS answers
        private List<string> ParseDNSAnswers(byte[] data, int offset)
        {
            List<string> answers = new List<string>();
            int currentOffset = offset;

            // Get answer count from header (bytes 6-7)
            int answerCount = BitConverter.ToUInt16(new byte[] { data[7], data[6] }, 0);

            for (int i = 0; i < answerCount && currentOffset < data.Length; i++)
            {
                try
                {
                    // Skip name field
                    while (currentOffset < data.Length && data[currentOffset] != 0)
                    {
                        if ((data[currentOffset] & 0xC0) == 0xC0)
                        {
                            currentOffset += 2;
                            break;
                        }
                        currentOffset += data[currentOffset] + 1;
                    }
                    currentOffset++;

                    // Skipping type and class (4 bytes)
                    currentOffset += 4;

                    // Skipping TTL (4 bytes)
                    currentOffset += 4;

                    // Getting the data length
                    int dataLength = BitConverter.ToUInt16(new byte[] { data[currentOffset + 1], data[currentOffset] }, 0);
                    currentOffset += 2;

                    // Extracting answer data
                    if (currentOffset + dataLength <= data.Length)
                    {
                        string answer = BitConverter.ToString(data, currentOffset, dataLength);
                        answers.Add(answer);
                        currentOffset += dataLength;
                    }
                }
                catch
                {
                    break;
                }
            }

            return answers;
        }

        private byte[] ExtractPayload(Packet packet)
        {
            TcpPacket tcpPacket = packet.Extract<TcpPacket>();

            if (tcpPacket?.PayloadData != null && tcpPacket.PayloadData.Length > 0)
                return tcpPacket.PayloadData;

            UdpPacket udpPacket = packet.Extract<UdpPacket>();

            if (udpPacket?.PayloadData != null && udpPacket.PayloadData.Length > 0)
                return udpPacket.PayloadData;

            return null;
        }

        private DNSQueryAnalytics AnalyzeDNSQueryLive(DNSQuery dnsQuery)
        {
            try
            {
                DNSQueryAnalytics dNSQueryAnalytics = dnsTDetective.AnalyzeQuery(dnsQuery);
                bool isStrange = dNSQueryAnalytics.potentialDNSTunneling;

                string message = "";

                if (isStrange)
                {
                    // Console.WriteLine($"Whoa! This packet with the source ip: '{dnsQuery.SourceIP}' is most likely a malware bruh.\n");
                    message = $"Whoa! This packet with the source ip: '{dnsQuery.SourceIP}' is most likely a malware bruh, it's mad sus!\n\n";
                    return dNSQueryAnalytics;
                }
                else
                {
                    message = $"This ip with the source ip: '{dnsQuery.SourceIP}' is most likely safe.\n\n";
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error analyzing DNS Query {dnsQuery}: {ex.Message}");
            }

            return null;
        }

        private HTTPSession ExtractHTTPSession(IPPacket ipPacket)
        {
            // Checking if the packet is an HTTP packet (TCP, Port 80 or 443)
            if (ipPacket.PayloadPacket is TcpPacket tcpPacket)
            {
                // Extracting the IPv4 layer
                IPv4Packet ipv4Packet = ipPacket.Extract<IPv4Packet>();

                if (ipv4Packet == null)
                {
                    // Console.WriteLine("Not a valid IPv4 packet.");
                    return null;
                }

                // Creating an HTTPSession object and populate it with extracted data
                HTTPSession httpsSession = new HTTPSession
                {
                    SourceIP = ipv4Packet.SourceAddress.ToString(),
                    DestinationIP = ipv4Packet.DestinationAddress.ToString(),
                    StartTime = DateTime.UtcNow, // Set to the current time or adjust as needed
                    PacketCount = 1,              // Increment this as needed in your session management
                    DataVolume = tcpPacket.PayloadData.Length, // Size of the current packet
                    Duration = TimeSpan.Zero,      // Duration will be calculated later
                    IsSuspicious = false,          // Initial assumption, can be updated later
                };

                return httpsSession;
            }
            // Console.WriteLine("Is not tcp apparently");
            return null;
        }
    }
}
