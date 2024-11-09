using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using Network_Packet_Analyzer_App.Core;
using Network_Packet_Analyzer_App.MVVM.Model;
using Network_Packet_Analyzer_App.MVVM.View;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Network_Packet_Analyzer_App.MVVM.ViewModel
{
    internal class DashboardViewModel : ObservableObject
    {
        private string protocolFilter;

        public string ProtocolFilter
        {
            get => protocolFilter;
            set
            {
                protocolFilter = value;
                //Console.WriteLine(ProtocolFilter);

                OnPropertyChanged(nameof(ProtocolFilter));
                ApplyFilter();
            }
        }

        public ObservableCollection<PacketInfo> FilteredPackets { get; }

        public ObservableCollection<PacketInfo> Packets { get; }
        public ObservableCollection<PacketInfo> SuspiciousDNSPackets { get; }
        public ObservableCollection<PacketInfo> SuspiciousHTTPPackets { get; }
        public ObservableCollection<PacketInfo> SuspiciousSSHPackets { get; }

        // For DNS Tunneling
        public PacketInfo selectedDNSPacketInfo { get; set; }
        public string selectedDNSReasons;

        public PacketInfo SelectedPacket
        {
            get => selectedDNSPacketInfo;
            set
            {
                selectedDNSPacketInfo = value;
                OnPropertyChanged(nameof(SelectedPacket));
                UpdateSelectedDNSReasons();
            }
        }

        public string SelectedReasons
        {
            get => selectedDNSReasons;
            set
            {
                selectedDNSReasons = value;
                OnPropertyChanged(nameof(SelectedReasons));
            }
        }

        // For HTTP Tunneling
        public PacketInfo selectedHTTPPacketInfo { get; set; }
        public string selectedHTTPReasons;

        public PacketInfo SelectedHTTPPacket
        {
            get => selectedHTTPPacketInfo;
            set
            {
                selectedHTTPPacketInfo = value;
                OnPropertyChanged(nameof(SelectedHTTPPacket));
                UpdateSelectedHTTPReasons();
            }
        }

        public string SelectedHTTPReasons
        {
            get => selectedHTTPReasons;
            set
            {
                selectedHTTPReasons = value;
                OnPropertyChanged(nameof(SelectedHTTPReasons));
            }
        }

        // For SSH Tunneling
        public PacketInfo selectedSSHPacketInfo { get; set; }
        public string selectedSSHReasons;

        public PacketInfo SelectedSSHPacket
        {
            get => selectedSSHPacketInfo;
            set
            {
                selectedSSHPacketInfo = value;
                OnPropertyChanged(nameof(SelectedSSHPacket));
                UpdateSelectedSSHReasons();
            }
        }

        public string SelectedSSHReasons
        {
            get => selectedSSHReasons;
            set
            {
                selectedSSHReasons = value;
                OnPropertyChanged(nameof(SelectedSSHReasons));
            }
        }

        public ICommand ClearPacketListCommand {  get; }
        public ICommand ClearSuspiciousDNSPacketListCommand { get; }
        public ICommand ClearSuspiciousHTTPPacketListCommand { get; }
        public ICommand ClearSuspiciousSSHPacketListCommand { get; }
        public ICommand DownloadDNSPacketsCommand { get; }
        public ICommand DownloadHTTPSPacketsCommand { get; }
        public ICommand DownloadSSHPacketsCommand { get; }
        public DashboardViewModel()
        {
            Packets = new ObservableCollection<PacketInfo>();
            SuspiciousDNSPackets = new ObservableCollection<PacketInfo>();
            SuspiciousHTTPPackets = new ObservableCollection<PacketInfo>();
            SuspiciousSSHPackets = new ObservableCollection<PacketInfo>();

            FilteredPackets = new ObservableCollection<PacketInfo>();

            ClearPacketListCommand = new RelayCommand(o =>
            {
                Packets.Clear();
            });

            ClearSuspiciousDNSPacketListCommand = new RelayCommand(o =>
            {
                SuspiciousDNSPackets.Clear();
            });

            ClearSuspiciousHTTPPacketListCommand = new RelayCommand(o =>
            {
                SuspiciousHTTPPackets.Clear();
            });

            ClearSuspiciousSSHPacketListCommand = new RelayCommand(o =>
            {
                SuspiciousSSHPackets.Clear();
            });

            DownloadDNSPacketsCommand = new RelayCommand(o =>
            {
                DownloadDNSPackets();
            });

            DownloadHTTPSPacketsCommand = new RelayCommand(o =>
            {
                DownloadHTTPPackets();
            });

            DownloadSSHPacketsCommand = new RelayCommand(o =>
            {
                DownloadSSHPackets();
            });
        }

        public void AddToPacketList(PacketInfo newPacket)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                Packets.Add(newPacket);
                ApplyFilter();
            });
        }

        public void AddToSuspiciousPacketList(PacketInfo newPacket)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                SuspiciousDNSPackets.Add(newPacket);
            });
        }

        public void AddToSuspiciousHttpsPacketList(PacketInfo newPacket)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                SuspiciousHTTPPackets.Add(newPacket);
            });
        }

        public void AddToSuspiciousSSHPacketList(PacketInfo newPacket)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                SuspiciousSSHPackets.Add(newPacket);
            });
        }

        public void AddToSuspiciousUrlList(PacketInfo newPacket)
        {
            /*Application.Current.Dispatcher.Invoke(() =>
            {
                SuspiciousUrls.Add(newPacket);
            });*/
        }

        private void UpdateSelectedDNSReasons()
        {
            if (SelectedPacket != null)
            {
                List<string> reasons = new List<string>();

                reasons.Add("Source: " + SelectedPacket.Source);
                reasons.Add("Destination: " + SelectedPacket.Destination);

                reasons.Add("\nReasons for flag:");

                if (SelectedPacket.DNSQueryInfo.hasAnomalousPatterns)
                    reasons.Add("- Suspicious subdomain length\n" +
                        "- Subdomain contains repeating patterns\n" +
                        "- Subdomain contains a high ratio of numeric characters");
                if (SelectedPacket.DNSQueryInfo.hasHighQueryRate)
                    reasons.Add("- Has a high query rate");
                if (SelectedPacket.DNSQueryInfo.hasUnusualStructure)
                    reasons.Add("- Has unusual structure");
                if (SelectedPacket.DNSQueryInfo.hasEncodedData)
                    reasons.Add("- High entropy and encoded data");
                if (SelectedPacket.DNSQueryInfo.hasUnusualQueryTypes)
                    reasons.Add("- Has unusual query types");

                SelectedReasons = string.Join("\n", reasons);
            }
            else
            {
                SelectedReasons = string.Empty;
            }
        }

        private void UpdateSelectedHTTPReasons()
        {
            if (SelectedHTTPPacket != null && SelectedHTTPPacket.HTTPSInfo != null && SelectedHTTPPacket.HTTPSInfo.potentialHTTPSTunneling)
            {
                List<string> reasons = new List<string>();

                reasons.Add("Source: " + SelectedHTTPPacket.Source);
                reasons.Add("Destination: " + SelectedHTTPPacket.Destination);

                reasons.Add("\nReasons for flag:");

                if (SelectedHTTPPacket.HTTPSInfo.hasHighSessionRate)
                    reasons.Add("- High session rate");
                if (SelectedHTTPPacket.HTTPSInfo.hasLongSessionDuration)
                    reasons.Add("- Has long session duration");
                if (SelectedHTTPPacket.HTTPSInfo.hasAnomalousPacketSizes)
                    reasons.Add("- Has huge packet sizes");
                if (SelectedHTTPPacket.HTTPSInfo.hasHighDataTransfer)
                    reasons.Add("- Has high data transfer");

                SelectedHTTPReasons = string.Join("\n", reasons);
            }
            else
            {
                SelectedHTTPReasons = string.Empty;
            }
        }

        private void UpdateSelectedSSHReasons()
        {
            if (SelectedSSHPacket != null && SelectedSSHPacket.SSHInfo != null && SelectedSSHPacket.SSHInfo.PotentialSSHTunneling)
            {
                List<string> reasons = new List<string>();

                reasons.Add("Source: " + SelectedSSHPacket.Source);
                reasons.Add("Destination: " + SelectedSSHPacket.Destination);

                reasons.Add("\nReasons for flag:");

                SelectedSSHReasons = string.Join("\n", reasons);
            }
            else
            {
                SelectedSSHReasons = string.Empty;
            }
        }

        private void ApplyFilter()
        {
            // Clear the filtered packets collection
            var filteredPackets = new ObservableCollection<PacketInfo>();

            // Populate filteredPackets based on ProtocolFilter
            foreach (var packet in Packets)
            {
                if (string.IsNullOrEmpty(ProtocolFilter) || packet.Protocol.ToLower().Contains(ProtocolFilter.ToLower()))
                {
                    //Console.WriteLine("Packet protocol: " + packet.Protocol);
                    filteredPackets.Add(packet);
                }
            }

            //Console.WriteLine("filteredPackets count: " + filteredPackets.Count());

            // Updating FilteredPackets to the new filtered list
            FilteredPackets.Clear();

            foreach (var packet in filteredPackets)
            {
                FilteredPackets.Add(packet);
            }

            // Ensuring only the latest 100 packets are kept
            while (FilteredPackets.Count > 100)
            {
                FilteredPackets.RemoveAt(0);
                Packets.RemoveAt(0);
            }
        }

        private void DownloadDNSPackets()
        {
            if (SuspiciousDNSPackets.Count == 0)
            {
                Console.WriteLine("No flagged DNS packets to save.");
                return;
            }

            var saveFileDialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "PCAP files (*.pcap)|*.pcap",
                Title = "Save Flagged DNS Packets",
                FileName = "FlaggedDNSPackets.pcap"
            };

            if (saveFileDialog.ShowDialog() == true)
            {
                string filePath = saveFileDialog.FileName;
                SaveFlaggedDNSPackets(filePath);
            }
        }

        private void DownloadHTTPPackets()
        {
            if (SuspiciousHTTPPackets.Count == 0)
            {
                Console.WriteLine("No flagged HTTP packets to save.");
                return;
            }

            var saveFileDialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "PCAP files (*.pcap)|*.pcap",
                Title = "Save Flagged HTTP Packets",
                FileName = "FlaggedHTTPPackets.pcap"
            };

            if (saveFileDialog.ShowDialog() == true)
            {
                string filePath = saveFileDialog.FileName;
                SaveFlaggedHTTPPackets(filePath);
            }
        }

        private void DownloadSSHPackets()
        {
            if (SuspiciousSSHPackets.Count == 0)
            {
                Console.WriteLine("No flagged SSH packets to save.");
                return;
            }

            var saveFileDialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "PCAP files (*.pcap)|*.pcap",
                Title = "Save Flagged SSH Packets",
                FileName = "FlaggedSSHPackets.pcap"
            };

            if (saveFileDialog.ShowDialog() == true)
            {
                string filePath = saveFileDialog.FileName;
                SaveFlaggedSSHPackets(filePath);
            }
        }

        public void SaveFlaggedDNSPackets(string filePath)
        {
            if (SuspiciousDNSPackets.Count == 0)
            {
                Console.WriteLine("No flagged DNS packets to save.");
                return;
            }

            // Using CaptureFileWriterDevice to write to a pcap file
            using (var writer = new CaptureFileWriterDevice(filePath))
            {
                writer.Open();
                foreach (var suspiciousPacket in SuspiciousDNSPackets)
                {
                    byte[] packetBytes = suspiciousPacket.DNSQueryInfo.dNSQuery.PacketData.Bytes;
                    DateTime currentTime = DateTime.Now;
                    ulong seconds = (ulong)(currentTime - new DateTime(1970, 1, 1)).TotalSeconds;
                    ulong microseconds =(ulong) currentTime.Millisecond * 1000;
                    PosixTimeval timestamp = new PosixTimeval(seconds, microseconds);

                    // Converting Packet to RawCapture
                    RawCapture rawCapture = new RawCapture(LinkLayers.Ethernet, timestamp, packetBytes);
                    writer.Write(rawCapture);
                }
                writer.Close();
            }

            Console.WriteLine($"Flagged DNS packets saved to {filePath}");
        }

        public void SaveFlaggedHTTPPackets(string filePath)
        {
            if (SuspiciousHTTPPackets.Count == 0)
            {
                Console.WriteLine("No flagged HTTP packets to save.");
                return;
            }

            // Using CaptureFileWriterDevice to write to a pcap file
            using (var writer = new CaptureFileWriterDevice(filePath))
            {
                writer.Open();
                foreach (var suspiciousPacket in SuspiciousHTTPPackets)
                {
                    byte[] packetBytes = suspiciousPacket.HTTPSInfo.hTTPSession.PacketData.Bytes;
                    DateTime currentTime = DateTime.Now;
                    ulong seconds = (ulong)(currentTime - new DateTime(1970, 1, 1)).TotalSeconds;
                    ulong microseconds = (ulong)currentTime.Millisecond * 1000;
                    PosixTimeval timestamp = new PosixTimeval(seconds, microseconds);

                    // Converting Packet to RawCapture
                    RawCapture rawCapture = new RawCapture(LinkLayers.Ethernet, timestamp, packetBytes);
                    writer.Write(rawCapture);
                }
                writer.Close();
            }

            Console.WriteLine($"Flagged HTTP packets saved to {filePath}");
        }

        public void SaveFlaggedSSHPackets(string filePath)
        {
            if (SuspiciousSSHPackets.Count == 0)
            {
                Console.WriteLine("No flagged SSH packets to save.");
                return;
            }

            // Using CaptureFileWriterDevice to write to a pcap file
            using (var writer = new CaptureFileWriterDevice(filePath))
            {
                writer.Open();
                foreach (var suspiciousPacket in SuspiciousSSHPackets)
                {
                    byte[] packetBytes = suspiciousPacket.SSHInfo.sshSession.PacketData.Bytes;
                    DateTime currentTime = DateTime.Now;
                    ulong seconds = (ulong)(currentTime - new DateTime(1970, 1, 1)).TotalSeconds;
                    ulong microseconds = (ulong)currentTime.Millisecond * 1000;
                    PosixTimeval timestamp = new PosixTimeval(seconds, microseconds);

                    // Converting Packet to RawCapture
                    RawCapture rawCapture = new RawCapture(LinkLayers.Ethernet, timestamp, packetBytes);
                    writer.Write(rawCapture);
                }
                writer.Close();
            }

            Console.WriteLine($"Flagged SSH packets saved to {filePath}");
        }
    }
}