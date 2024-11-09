using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using PacketDotNet;
using SharpPcap;

namespace Network_Packet_Analyzer_App.Core
{
    public class DNSQuery
    {
        public string QueryDomain { get; set; } // Full query domain
        public string SourceIP { get; set; } // Source IP of query
        public DateTime Timestamp { get; set; } // When the query was made
        public ushort TransactionID { get; set; } // DNS transaction ID
        public List<string> Subdomains { get; set; } // List of subdomain parts
        public string RootDomain { get; set; } // Root domain
        public QueryType QueryType { get; set; } // Type of DNS query (A, AAAA, TXT, etc)
        public int QueryLength { get; set; } // Total length of query
        public bool RecursionDesired { get; set; } // If recursion was requested
        public ushort QueryClass { get; set; } // Query class (usually IN for Internet)
        public List<string> Answers { get; set; } // Any answers received
        public int ResponseLength { get; set; } // Length of response if any
        public bool IsTruncated { get; set; } // If response was truncated
        public Packet PacketData { get; set; } // To store the packet for downloading and accessing later

        public DNSQuery()
        {
            Subdomains = new List<string>();
            Answers = new List<string>();
            Timestamp = DateTime.UtcNow;
        }
    }

    public class DNSQueryAnalytics
    {
        public bool hasAnomalousPatterns;
        public bool hasHighQueryRate;
        public bool hasUnusualStructure;
        public bool hasEncodedData;
        public bool hasUnusualQueryTypes;

        public bool potentialDNSTunneling;

        public DNSQuery dNSQuery;

        public DNSQueryAnalytics(bool aPatterns, bool hqRate, bool uStructure, bool encData, bool uqTypes, bool potentialDNST)
        {
            hasAnomalousPatterns = aPatterns;
            hasHighQueryRate = hqRate;
            hasUnusualStructure = uStructure;
            hasEncodedData = encData;
            hasUnusualQueryTypes = uqTypes;
            potentialDNSTunneling = potentialDNST;
        }
    }

    public class DNSTunnelingDetective
    {
        private readonly Dictionary<string, Queue<DNSQuery>> hostQueryHistory;
        private readonly int queryThreshold = 100; // Maximum queries per timeWindow
        private readonly TimeSpan timeWindow = TimeSpan.FromMinutes(5);
        private readonly int suspiciousSubdomainLength = 30;
        private readonly double suspiciousEntropyThreshold = 4.0;
        private readonly double suspiciousNumericRatio = 0.4;

        public DNSTunnelingDetective()
        {
            hostQueryHistory = new Dictionary<string, Queue<DNSQuery>>();
        }

        public DNSQueryAnalytics AnalyzeQuery(DNSQuery query)
        {
            if (query == null || string.IsNullOrEmpty(query.QueryDomain))
                return new DNSQueryAnalytics(false, false, false, false, false, false);

            // Running all detection checks
            bool hasAnomalousPatterns = CheckForAnomalousPatterns(query);
            bool hasHighQueryRate = CheckQueryRate(query);
            bool hasUnusualStructure = CheckQueryStructure(query);
            bool hasEncodedData = CheckForEncodedData(query);
            bool hasUnusualQueryTypes = CheckUnusualQueryTypes(query);

            // To count how many indicators are present
            int indicators = 0;
            if (hasAnomalousPatterns) indicators++;
            if (hasHighQueryRate) indicators++;
            if (hasUnusualStructure) indicators++;
            if (hasEncodedData) indicators++;
            if (hasUnusualQueryTypes) indicators++;

            // indicators >= 2; Require at least 2 indicators
            DNSQueryAnalytics queryAnalytics = new DNSQueryAnalytics(hasAnomalousPatterns, hasHighQueryRate, hasUnusualStructure,
                                                                     hasEncodedData, hasUnusualQueryTypes, indicators >= 2);
            queryAnalytics.dNSQuery = query;

            return queryAnalytics;
        }

        private bool CheckForAnomalousPatterns(DNSQuery query)
        {
            // Checking subdomain lengths
            if (query.Subdomains.Any(s => s.Length > suspiciousSubdomainLength))
                return true;

            // Checking for repeating patterns in subdomains
            foreach (string subdomain in query.Subdomains)
            {
                Regex repeatingPattern = new System.Text.RegularExpressions.Regex(@"(.+?)\1{2,}");

                if (repeatingPattern.IsMatch(subdomain))
                    return true;

                // Checking for high ratio of numeric characters
                double numericRatio = (double)subdomain.Count(char.IsDigit) / subdomain.Length;
                if (numericRatio > suspiciousNumericRatio)
                    return true;
            }

            return false;
        }

        // For thread safety
        private readonly object accessLock = new object();

        private bool CheckQueryRate(DNSQuery query)
        {
            DateTime now = DateTime.UtcNow;

            if (query == null || string.IsNullOrEmpty(query.SourceIP))
            {
                return false;
            }

            // Locking access to hostQueryHistory because I'm dealing with concurrent threads.
            lock (accessLock)
            {
                // Initializing or updating query history for this IP
                if (!hostQueryHistory.ContainsKey(query.SourceIP))
                {
                    hostQueryHistory[query.SourceIP] = new Queue<DNSQuery>();
                }

                // Removing old queries
                while (hostQueryHistory[query.SourceIP].Count > 0 &&
                       now - hostQueryHistory[query.SourceIP].Peek().Timestamp > timeWindow)
                {
                    hostQueryHistory[query.SourceIP].Dequeue();
                }

                hostQueryHistory[query.SourceIP].Enqueue(query);

                // Checking query rate and patterns
                Queue<DNSQuery> recentQueries = hostQueryHistory[query.SourceIP];

                // Checking overall query rate
                if (recentQueries.Count > queryThreshold)
                    return true;

                // Checking for rapid identical queries
                Int32 identicalQueries = recentQueries.Count(q => q != null && q.QueryDomain == query.QueryDomain);

                if (identicalQueries > queryThreshold / 4)
                    return true;

                return false;
            }
        }

        private bool CheckQueryStructure(DNSQuery query)
        {
            // Checking for unusual character combinations
            Regex unusualPattern = new System.Text.RegularExpressions.Regex(@"[0-9a-f]{8,}|[a-zA-Z0-9+/=]{16,}");

            foreach (string subdomain in query.Subdomains)
            {
                if (unusualPattern.IsMatch(subdomain))
                    return true;

                // Checking for excessive use of hyphens or underscores
                int hyphenCount = subdomain.Count(c => c == '-');
                int underscoreCount = subdomain.Count(c => c == '_');
                if ((double)(hyphenCount + underscoreCount) / subdomain.Length > 0.2)
                    return true;
            }

            // Checking total query length
            if (query.QueryLength > 200) // Unusually long DNS query
                return true;

            return false;
        }

        private bool CheckForEncodedData(DNSQuery query)
        {
            foreach (string subdomain in query.Subdomains)
            {
                // Calculating entropy
                double entropy = CalculateEntropy(subdomain);
                if (entropy > suspiciousEntropyThreshold)
                    return true;

                // Checking for base64-like patterns
                Regex base64Pattern = new System.Text.RegularExpressions.Regex(@"^[A-Za-z0-9+/=]{10,}$");
                if (base64Pattern.IsMatch(subdomain))
                    return true;

                // Checking for hex-encoded data
                Regex hexPattern = new System.Text.RegularExpressions.Regex(@"^[A-Fa-f0-9]{10,}$");
                if (hexPattern.IsMatch(subdomain))
                    return true;
            }

            return false;
        }

        private bool CheckUnusualQueryTypes(DNSQuery query)
        {
            // Checking for unusual query types often used in tunneling
            if (query.QueryType == QueryType.TXT ||
                query.QueryType == QueryType.NULL ||
                query.QueryType == QueryType.SRV)
            {
                // If using these types with large queries or high frequency
                if (query.QueryLength > 100 ||
                    hostQueryHistory[query.SourceIP].Count(q => q.QueryType == query.QueryType) > 20)
                    return true;
            }

            // Checking for response size anomalies
            if (query.ResponseLength > 0 && query.ResponseLength > 512) // If it is an unusually large DNS response
                return true;

            return false;
        }

        private double CalculateEntropy(string text)
        {
            Dictionary<char, int> frequencies = new Dictionary<char, int>();
            foreach (char c in text)
            {
                if (!frequencies.ContainsKey(c))
                    frequencies[c] = 0;
                frequencies[c]++;
            }

            double entropy = 0;
            int length = text.Length;

            foreach (Int32 freq in frequencies.Values)
            {
                double probability = (double)freq / length;
                entropy -= probability * Math.Log(probability) / Math.Log(2.0);
            }

            return entropy;
        }

        public void CleanupOldEntries()
        {
            DateTime now = DateTime.UtcNow;

            List<string> keysToRemove = new List<string>();

            foreach (var kvp in hostQueryHistory)
            {
                while (kvp.Value.Count > 0 && now - kvp.Value.Peek().Timestamp > timeWindow)
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
                hostQueryHistory.Remove(key);
            }
        }
    }

    public enum QueryType
    {
        A = 1,
        NS = 2,
        CNAME = 5,
        SOA = 6,
        PTR = 12,
        MX = 15,
        TXT = 16,
        AAAA = 28,
        SRV = 33,
        NULL = 10
    }
}