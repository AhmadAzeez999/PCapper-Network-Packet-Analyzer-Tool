using System;
using System.Collections.Generic;
using System.Linq;
using PacketDotNet;
using SharpPcap;

namespace Network_Packet_Analyzer_App.Core
{
    public class HTTPSession
    {
        public string SourceIP { get; set; }      // Source IP of the HTTPS connection
        public string DestinationIP { get; set; } // Destination IP of the HTTPS connection
        public DateTime StartTime { get; set; }   // Start time of the HTTPS session
        public int PacketCount { get; set; }      // Total number of packets in the session
        public int DataVolume { get; set; }       // Total data volume (bytes)
        public TimeSpan Duration { get; set; }    // Session duration
        public bool IsSuspicious { get; set; }    // Flag for suspicious behavior
        public Packet PacketData { get; set; }

        public HTTPSession()
        {
            StartTime = DateTime.UtcNow;
            PacketCount = 0;
            DataVolume = 0;
        }
    }

    public class HTTPSTunnelingAnalytics
    {
        public bool hasHighSessionRate;
        public bool hasLongSessionDuration;
        public bool hasAnomalousPacketSizes;
        public bool hasHighDataTransfer;
        public bool potentialHTTPSTunneling;

        public HTTPSession hTTPSession;

        public HTTPSTunnelingAnalytics(bool highRate, bool longDuration, bool anomalousSizes, bool highData, bool potentialTunneling)
        {
            hasHighSessionRate = highRate;
            hasLongSessionDuration = longDuration;
            hasAnomalousPacketSizes = anomalousSizes;
            hasHighDataTransfer = highData;
            potentialHTTPSTunneling = potentialTunneling;
        }
    }

    public class HTTPSTunnelingDetective
    {
        private readonly Dictionary<string, Queue<HTTPSession>> sessionHistory;
        private readonly int sessionThreshold = 50;                      // Threshold for sessions per time window
        private readonly TimeSpan timeWindow = TimeSpan.FromMinutes(10); // Time window to check session rates
        private readonly int maxPacketSize = 5000;                       // Size threshold to detect anomalous packet sizes
        private readonly int maxSessionDataVolume = 500000;              // Data threshold in bytes for a session

        public HTTPSTunnelingDetective()
        {
            sessionHistory = new Dictionary<string, Queue<HTTPSession>>();
        }

        public HTTPSTunnelingAnalytics AnalyzeSession(HTTPSession session)
        {
            // Check for tunneling indicators
            bool hasHighSessionRate = CheckSessionRate(session);
            bool hasLongSessionDuration = session.Duration > TimeSpan.FromMinutes(5);
            bool hasAnomalousPacketSizes = CheckAnomalousPacketSizes(session);
            bool hasHighDataTransfer = session.DataVolume > maxSessionDataVolume;

            // Count the indicators for tunneling
            int indicators = 0;
            if (hasHighSessionRate) indicators++;
            if (hasLongSessionDuration) indicators++;
            if (hasAnomalousPacketSizes) indicators++;
            if (hasHighDataTransfer) indicators++;

            // Determine if there is potential tunneling
            bool potentialHTTPSTunneling = indicators >= 2;
            HTTPSTunnelingAnalytics hTTPSTunnelingAnalytics = new HTTPSTunnelingAnalytics(hasHighSessionRate, hasLongSessionDuration, hasAnomalousPacketSizes, hasHighDataTransfer, potentialHTTPSTunneling);
            hTTPSTunnelingAnalytics.hTTPSession = session;

            return hTTPSTunnelingAnalytics;
        }

        private bool CheckSessionRate(HTTPSession session)
        {
            DateTime now = DateTime.UtcNow;
            string sourceIP = session.SourceIP;

            if (session == null || string.IsNullOrEmpty(sourceIP))
                return false;

            // Ensure thread-safety
            lock (sessionHistory)
            {
                if (!sessionHistory.ContainsKey(sourceIP))
                {
                    sessionHistory[sourceIP] = new Queue<HTTPSession>();
                }

                // Remove old sessions outside the time window
                while (sessionHistory[sourceIP].Count > 0 && now - sessionHistory[sourceIP].Peek().StartTime > timeWindow)
                {
                    sessionHistory[sourceIP].Dequeue();
                }

                // Add the current session
                sessionHistory[sourceIP].Enqueue(session);

                // Check if session rate exceeds the threshold
                return sessionHistory[sourceIP].Count > sessionThreshold;
            }
        }

        private bool CheckAnomalousPacketSizes(HTTPSession session)
        {
            // Anomalous packet size detection, typically over 1500 bytes may indicate tunneling
            return session.PacketCount > 0 && session.DataVolume / session.PacketCount > maxPacketSize;
        }

        public void CleanupOldEntries()
        {
            DateTime now = DateTime.UtcNow;
            List<string> keysToRemove = new List<string>();

            foreach (var kvp in sessionHistory)
            {
                while (kvp.Value.Count > 0 && now - kvp.Value.Peek().StartTime > timeWindow)
                {
                    kvp.Value.Dequeue();
                }

                if (kvp.Value.Count == 0)
                {
                    keysToRemove.Add(kvp.Key);
                }
            }

            foreach (string key in keysToRemove)
            {
                sessionHistory.Remove(key);
            }
        }
    }
}
