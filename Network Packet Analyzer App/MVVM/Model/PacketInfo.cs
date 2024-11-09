using Network_Packet_Analyzer_App.Core;
using System;

namespace Network_Packet_Analyzer_App.MVVM.Model
{
    public class PacketInfo
    {
        public DateTime Time { get; set; }
        public string Protocol { get; set; }
        public string Source { get; set; }
        public string Destination { get; set; }
        public int Length { get; set; }
        public string Info { get; set; }

        public DNSQueryAnalytics DNSQueryInfo { get; set; }
        public HTTPSTunnelingAnalytics HTTPSInfo { get; set; }
        public SSHTunnelingAnalytics SSHInfo { get; set; }

        public bool containsSuspiciousUrl;
    }
}