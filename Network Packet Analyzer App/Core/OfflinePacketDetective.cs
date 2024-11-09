using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Net.Http;
using System.Threading;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;
using SharpPcap;
using PacketDotNet;
using SharpPcap.LibPcap;
using Network_Packet_Analyzer_App.MVVM.Model;
using System.Security.Policy;
using System.Collections;
using System.Linq;
using System.Net;

namespace Network_Packet_Analyzer_App.Core
{
    internal class OfflinePacketDetective
    {
        private readonly string virusTotalApiKey;
        private readonly SemaphoreSlim rateLimiter;
        private readonly HttpClient httpClient;
        private DateTime lastRequestTime;
        private int requestCount;
        private const int REQUEST_LIMIT = 4;
        private const int TIME_WINDOW_MINUTES = 1;
        private readonly Regex urlRegex = new Regex(@"https?://[^\s<>""']+", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private DNSTunnelingDetective dnsTDetective;
        private HTTPSTunnelingDetective httpsTDetective;
        private SSHTunnelingDetective sshTDetective;

        public event Action<string> PacketScanned;

        public OfflinePacketDetective(string virusTotalApiKey)
        {
            this.virusTotalApiKey = virusTotalApiKey;
            rateLimiter = new SemaphoreSlim(1, 1);
            httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Add("x-apikey", this.virusTotalApiKey);
            lastRequestTime = DateTime.MinValue;
            requestCount = 0;

            dnsTDetective = new DNSTunnelingDetective();
            httpsTDetective = new HTTPSTunnelingDetective();
            sshTDetective = new SSHTunnelingDetective();
        }

        public async Task AnalyzePcapFile(string pcapPath)
        {
            ICaptureDevice device = null;

            try
            {
                device = new CaptureFileReaderDevice(pcapPath);
                device.Open();

                /*var urls = ExtractUrls(device);

                Console.WriteLine($"Found {urls.Count} unique URLs in the PCAP file");

                foreach (var url in urls)
                {
                    await AnalyzeUrl(url);
                }*/

                HashSet<DNSQuery> dnsQueries = await Task.Run(() => ExtractDnsQueries(device));

                Console.WriteLine($"Found {dnsQueries.Count} DNS Queries.");
                Console.WriteLine($"Scanning the DNS Queries...");

                /*foreach (var dnsQuery in dnsQueries)
                {
                    await Task.Run(() => AnalyzeDNSQuery(dnsQuery));
                }*/

                // Process each DNS query asynchronously without blocking the UI
                var tasks = dnsQueries.Select(dnsQuery => Task.Run(() => AnalyzeDNSQuery(dnsQuery)));
                await Task.WhenAll(tasks); // Wait for all queries to be processed
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error analyzing PCAP file: {ex.Message}");
            }
            finally
            {
                if (device != null)
                {
                    device.Close();
                    device.Dispose();
                }
            }
        }

        public async Task AnalyzePcapFileForHTTPS(string pcapPath)
        {
            ICaptureDevice device = null;

            try
            {
                device = new CaptureFileReaderDevice(pcapPath);
                device.Open();

                HashSet<HTTPSession> httpSessions = await Task.Run(() => ExtractHTTPSession(device));

                Console.WriteLine($"Found {httpSessions.Count} HTTP Sessions.");

                // Process each HTTP session asynchronously without blocking the UI
                var tasks = httpSessions.Select(httpSession => Task.Run(() => AnalyzeHTTPPacket(httpSession)));
                await Task.WhenAll(tasks); // Wait for all queries to be processed
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error analyzing PCAP file: {ex.Message}");
            }
            finally
            {
                if (device != null)
                {
                    device.Close();
                    device.Dispose();
                }
            }
        }

        public async Task AnalyzePcapFileForSSH(string pcapPath)
        {
            ICaptureDevice device = null;

            try
            {
                device = new CaptureFileReaderDevice(pcapPath);
                device.Open();

                HashSet<Packet> sshPackets = await Task.Run(() => ExtractSSHPacket(device));

                Console.WriteLine($"Found {sshPackets.Count} Packets.");

                // Process each HTTP session asynchronously without blocking the UI
                var tasks = sshPackets.Select(sshPacket => Task.Run(() => AnalyzeSSHPacket(sshPacket)));

                await Task.WhenAll(tasks); // Wait for all queries to be processed
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error analyzing PCAP file: {ex.Message}");
            }
            finally
            {
                if (device != null)
                {
                    device.Close();
                    device.Dispose();
                }
            }
        }

        private HashSet<DNSQuery> ExtractDnsQueries(ICaptureDevice device)
        {
            HashSet<DNSQuery> dnsQueries = new HashSet<DNSQuery>();
            PacketCapture e;

            while (device.GetNextPacket(out e) == GetPacketStatus.PacketRead)
            {
                RawCapture rawPacket = e.GetPacket();
                Packet packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

                // Check if the packet is an IP packet
                if (packet.PayloadPacket is IPPacket ipPacket)
                {
                    // Check if the payload is a UDP packet
                    if (ipPacket.PayloadPacket is UdpPacket udpPacket)
                    {
                        // Check if it's a DNS packet (typically on port 53)
                        if (udpPacket.DestinationPort == 53 || udpPacket.SourcePort == 53)
                        {
                            var dnsPayload = ExtractPayload(packet);
                            if (dnsPayload != null && dnsPayload.Length >= 12) // DNS header is at least 12 bytes
                            {
                                try
                                {
                                    DNSQuery dnsQuery = new DNSQuery
                                    {
                                        // Extract Transaction ID (first 2 bytes)
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

                                    // Process domain parts
                                    string[] domainParts = dnsQuery.QueryDomain.Split('.');
                                    if (domainParts.Length >= 2)
                                    {
                                        // Get the last two parts for root domain
                                        dnsQuery.RootDomain = domainParts[domainParts.Length - 2] + "." + domainParts[domainParts.Length - 1];
                                        // Get all parts except the last two for subdomains
                                        dnsQuery.Subdomains = domainParts.Take(domainParts.Length - 2).ToList();
                                    }
                                    else
                                    {
                                        dnsQuery.RootDomain = dnsQuery.QueryDomain;
                                        dnsQuery.Subdomains = new List<string>();
                                    }

                                    // Parse answers if response packet
                                    if (udpPacket.SourcePort == 53)
                                    {
                                        dnsQuery.Answers = ParseDNSAnswers(dnsPayload, offset + 4);
                                        dnsQuery.ResponseLength = dnsPayload.Length;
                                    }

                                    dnsQueries.Add(dnsQuery);
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"Error processing DNS packet: {ex.Message}");
                                }
                            }
                        }
                    }
                }
            }
            return dnsQueries;
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

                    // Skip type and class (4 bytes)
                    currentOffset += 4;

                    // Skip TTL (4 bytes)
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

        private HashSet<HTTPSession> ExtractHTTPSession(ICaptureDevice device)
        {
            HashSet<HTTPSession> httpSessions = new HashSet<HTTPSession>();
            PacketCapture e;

            while (device.GetNextPacket(out e) == GetPacketStatus.PacketRead)
            {
                RawCapture rawPacket = e.GetPacket();
                Packet packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

                // Checking if the packet is an HTTP packet (TCP, Port 80 or 443)
                if (packet is TcpPacket tcpPacket)
                {
                    // Extracting the IPv4 layer
                    IPv4Packet ipv4Packet = packet.Extract<IPv4Packet>();
                    if (ipv4Packet == null)
                    {
                        Console.WriteLine("Not a valid IPv4 packet.");
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
                        PacketData = packet
                    };

                    httpSessions.Add(httpsSession);
                }
            }

            return httpSessions;
        }

        private HashSet<Packet> ExtractSSHPacket(ICaptureDevice device)
        {
            HashSet<Packet> packets = new HashSet<Packet>();
            PacketCapture e;

            while (device.GetNextPacket(out e) == GetPacketStatus.PacketRead)
            {
                RawCapture rawPacket = e.GetPacket();
                Packet packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

                packets.Add(packet);
            }

            return packets;
        }

        private void AnalyzeDNSQuery(DNSQuery dnsQuery)
        {
            try
            {
                bool isSus = dnsTDetective.AnalyzeQuery(dnsQuery).potentialDNSTunneling;

                string message = "";

                if (isSus)
                {
                    Console.WriteLine($"Whoa!'{dnsQuery.PacketData}' is most likely using DNS Tunneling.\n");
                    message = $"Whoa! '{dnsQuery.PacketData}' is most likely using DNS Tunneling.\n\n";
                }
                else
                {
                    // message = $"This packet with the source ip: '{dnsQuery.SourceIP}' is most likely safe.\n\n";
                }

                PacketScanned?.Invoke(message);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error analyzing DNS Query {dnsQuery.PacketData}: {ex.Message}");
            }
        }

        public void AnalyzeHTTPPacket(HTTPSession httpSession)
        {
            bool isSuspicious = httpsTDetective.AnalyzeSession(httpSession).potentialHTTPSTunneling;

            string message = "";

            if (isSuspicious)
            {
                Console.WriteLine($"Whoa! The packet with this ip: '{httpSession.PacketData}' is most likely using HTTPS Tunneling.\n");
                message = $"Whoa! The packet with this ip: '{httpSession.PacketData}' is most likely using HTTPS Tunneling.\n\n";
            }
            else
            {
                // message = $"The packet with this ip: '{httpSession.SourceIP}' is most likely safe.\n\n";
            }

            PacketScanned?.Invoke(message);

            /*if (malDetectML.IsUrlUnsafe(url))
            {
                Console.WriteLine($"{url} is not safe.");
                packetInfo.containsSuspiciousUrl = true;
            }
            else
            {
                Console.WriteLine($"{url} is safe.");
                packetInfo.containsSuspiciousUrl = false;
            }*/
        }

        public void AnalyzeSSHPacket(Packet sshPacket)
        {
            bool isSuspicious = sshTDetective.AnalyzeSSHPacket(sshPacket).PotentialSSHTunneling;

            string message = "";

            if (isSuspicious)
            {
                Console.WriteLine($"'{sshPacket}' is most likely using SSH Tunneling.\n");
                message = $"'{sshPacket}' is most likely using SSH Tunneling.\n\n";
            }
            else
            {
                // message = $"'{sshPacket}' is most likely safe.\n\n";
            }

            PacketScanned?.Invoke(message);
        }
    }
}