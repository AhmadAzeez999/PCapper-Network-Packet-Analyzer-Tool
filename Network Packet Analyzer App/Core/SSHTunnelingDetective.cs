using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using PacketDotNet;
using SharpPcap;

namespace Network_Packet_Analyzer_App.Core
{
    public class SSHSession
    {
        public string SourceIP { get; set; }              // Source IP of SSH traffic
        public string DestinationIP { get; set; }         // Destination IP (SSH server)
        public DateTime SessionStart { get; set; }        // Start time of the SSH session
        public List<int> PayloadLengths { get; set; }     // List of payload sizes for entropy analysis
        public bool IsEncrypted { get; set; }             // Indicates if the session uses encryption

        public Packet PacketData { get; set; }

        public SSHSession()
        {
            PayloadLengths = new List<int>();
            SessionStart = DateTime.UtcNow;
            IsEncrypted = true; // Assuming SSH is encrypted by default
        }
    }

    public class SSHTunnelingAnalytics
    {
        public bool HasHighConnectionFrequency { get; set; }
        public bool HasLongDuration { get; set; }
        public bool HasConsistentPayloadPatterns { get; set; }
        public bool PotentialSSHTunneling { get; set; }

        public SSHSession sshSession;

        public SSHTunnelingAnalytics(bool highFreq, bool longDuration, bool consistentPayload, bool potentialTunneling)
        {
            HasHighConnectionFrequency = highFreq;
            HasLongDuration = longDuration;
            HasConsistentPayloadPatterns = consistentPayload;
            PotentialSSHTunneling = potentialTunneling;
        }
    }

    public class SSHTunnelingDetective
    {
        private readonly Dictionary<string, SSHSession> activeSessions;
        private readonly int connectionThreshold = 50;    // Max connections per timeframe for threshold
        private readonly TimeSpan timeWindow = TimeSpan.FromMinutes(5);
        private readonly TimeSpan longDurationThreshold = TimeSpan.FromMinutes(15);
        private readonly double suspiciousEntropyThreshold = 3.5;

        public SSHTunnelingDetective()
        {
            activeSessions = new Dictionary<string, SSHSession>();
        }

        public SSHTunnelingAnalytics AnalyzeSession(Packet packet)
        {
            // Filtering for SSH traffic, usually on port 22
            if (!(packet is TcpPacket tcpPacket) || tcpPacket.DestinationPort != 22)
                return new SSHTunnelingAnalytics(false, false, false, false);

            Console.WriteLine("Found SSH packet");

            string srcIP = packet.Extract<IPv4Packet>().SourceAddress.ToString();
            string destIP = packet.Extract<IPv4Packet>().DestinationAddress.ToString();

            // Retrieving or initializing session for this src-dest pair
            if (!activeSessions.ContainsKey(srcIP))
                activeSessions[srcIP] = new SSHSession { SourceIP = srcIP, DestinationIP = destIP };

            SSHSession session = activeSessions[srcIP];
            session.PayloadLengths.Add(tcpPacket.PayloadData.Length);

            session.PacketData = packet;

            // Running checks to detect SSH tunneling
            bool highConnectionFrequency = CheckConnectionFrequency(session);
            bool longDuration = CheckSessionDuration(session);
            bool consistentPayloadPattern = CheckPayloadPatterns(session);

            // Require at least two indicators to flag as potential SSH tunneling
            int indicators = 0;
            if (highConnectionFrequency) indicators++;
            if (longDuration) indicators++;
            if (consistentPayloadPattern) indicators++;

            bool potentialSSHTunneling = indicators >= 2;

            SSHTunnelingAnalytics sshTunnelingAnalytics = new SSHTunnelingAnalytics(highConnectionFrequency, longDuration, consistentPayloadPattern, potentialSSHTunneling);
            sshTunnelingAnalytics.sshSession = session;

            return sshTunnelingAnalytics;
        }

        public SSHTunnelingAnalytics AnalyzeSSHPacket(Packet sshPacket)
        {
            return AnalyzeSession(sshPacket);
        }

        private bool CheckConnectionFrequency(SSHSession session)
        {
            // Tracking recent connections and determine if frequency is high
            DateTime now = DateTime.UtcNow;

            if ((now - session.SessionStart) <= timeWindow && session.PayloadLengths.Count > connectionThreshold)
            {
                return true;
            }

            return false;
        }

        private bool CheckSessionDuration(SSHSession session)
        {
            // Identify if the session has exceeded a typical SSH session duration threshold
            return DateTime.UtcNow - session.SessionStart > longDurationThreshold;
        }

        private bool CheckPayloadPatterns(SSHSession session)
        {
            // Calculating entropy to identify consistent encrypted payload patterns
            double avgPayloadLength = session.PayloadLengths.Average();
            double payloadEntropy = CalculateEntropy(session.PayloadLengths);

            return payloadEntropy < suspiciousEntropyThreshold || avgPayloadLength > 1000;
        }

        private double CalculateEntropy(List<int> data)
        {
            // Calculating entropy based on payload lengths to identify repetition
            var frequencies = new Dictionary<int, int>();
            foreach (var length in data)
            {
                if (!frequencies.ContainsKey(length))
                    frequencies[length] = 0;
                frequencies[length]++;
            }

            double entropy = 0;
            int dataSize = data.Count;
            foreach (var freq in frequencies.Values)
            {
                double probability = (double)freq / dataSize;
                entropy -= probability * Math.Log(probability) / Math.Log(2.0);
            }

            return entropy;
        }

        public void CleanupOldSessions()
        {
            // Remove old sessions to manage memory and keep analysis fresh
            DateTime now = DateTime.UtcNow;

            var keysToRemove = activeSessions
                .Where(kvp => now - kvp.Value.SessionStart > timeWindow)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (string key in keysToRemove)
            {
                activeSessions.Remove(key);
            }
        }
    }
}
