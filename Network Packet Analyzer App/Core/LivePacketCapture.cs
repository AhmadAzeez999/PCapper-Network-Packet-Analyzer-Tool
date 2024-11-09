using System;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Threading.Tasks;
using Network_Packet_Analyzer_App.MVVM.Model;
using System.Diagnostics;
using System.Collections.ObjectModel;

public class AvailableDevice
{
    public string Name { get; set; }
    public int Number { get; set; }
}

namespace Network_Packet_Analyzer_App.Core
{
    internal class LivePacketCapture
    {
        // Variable for storing the network device that has been selected for live capture
        private ILiveDevice selectedDevice;

        // An event that will notify listeners when a packet is captured
        public event Action<PacketInfo> PacketCaptured;

        private OnlinePacketDetective packetDetective = new OnlinePacketDetective();

        public ObservableCollection<AvailableDevice> ListAvailableDevices()
        {
            // For capturing all the currently available network devices
            CaptureDeviceList devices = CaptureDeviceList.Instance;

            ObservableCollection<AvailableDevice> availableDevices = new ObservableCollection<AvailableDevice>();

            // Displaying the devices
            for (int i = 0; i < devices.Count; i++)
            {
                ILiveDevice device = devices[i];
                //Console.WriteLine($"{i}) {device.Description}");
                availableDevices.Add(new AvailableDevice() { Name = device.Description, Number = i});
            }

            return availableDevices;
        }

        public bool SelectDevice(int index)
        {
            try
            {
                CaptureDeviceList devices = CaptureDeviceList.Instance;

                // Making sure it is not above or below the number of available devices
                if (index >= 0 && index < devices.Count)
                {
                    selectedDevice = devices[index];
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Oof! error selecting device: {ex.Message}");
                return false;
            }
        }

        public ILiveDevice GetDevice(int index)
        {
            return selectedDevice;
        }

        public async Task StartCapture()
        {
            // If no devices where selected (shouldn't be possible in the app)
            if (selectedDevice == null)
            {
                throw new InvalidOperationException("No device selected");
            }

            try
            {
                // This opens the selected device in promiscuous mode
                // Which means it captures all packets, not just those destined for the device
                selectedDevice.Open(new DeviceConfiguration
                {
                    Mode = DeviceModes.Promiscuous,
                    ReadTimeout = 1000
                });

                // This registers the event handler "DeviceOnPacketArrival"
                // For when a packet is captured
                selectedDevice.OnPacketArrival += DeviceOnPacketArrival;

                selectedDevice.StartCapture();

                // Starts capturing packets asynchronously, keeping the UI responsive
                await Task.Run(() =>
                {
                    //Console.WriteLine("Packet capture started...");
                });
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error during capture: {e.Message}");
                StopCapture();
            }
        }

        public void StopCapture()
        {
            try
            {
                if (selectedDevice != null && selectedDevice.Started)
                {
                    selectedDevice.StopCapture();
                    selectedDevice.Close();
                    // Console.WriteLine("DNS Capture stopped.");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error stopping capture: {e.Message}");
            }
        }

        private void DeviceOnPacketArrival(object sender, PacketCapture pCap)
        {
            try
            {
                RawCapture rawPacket = pCap.GetPacket();

                // Parsing the raw packet to a higher level packet representation (like IP and TCP)
                // ParsePacket converts the raw byte data into structured objects that represent each layer of the packet
                Packet packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

                // Checking if the payload is an ip packet and if it's a TCP packet
                if (packet.PayloadPacket is IPPacket ipPacket)
                {
                    if (ipPacket.PayloadPacket is UdpPacket udpPacket)
                    {
                        // Checking if the UDP packet uses DNS
                        if (IsDNSTraffic(udpPacket))
                        {
                            PacketInfo packetInfo = CreateDNSPacketInfo(ipPacket, udpPacket, rawPacket);

                            packetDetective.AnalyzeDNSPacket(packet, ref packetInfo);

                            // Console.WriteLine("Is DNST: " + (packetInfo.DNSQueryInfo != null));
                            PacketCaptured?.Invoke(packetInfo);
                        }
                    }
                    else if (ipPacket.PayloadPacket is TcpPacket tcpPacket)
                    {
                        // Checking if the TCP packet uses DNS
                        if (IsHttpTraffic(tcpPacket))
                        {
                            PacketInfo packetInfo = CreateHttpPacketInfo(ipPacket, tcpPacket, rawPacket);

                            packetDetective.AnalyzeHTTPPacket(ipPacket, ref packetInfo);
                            packetInfo.HTTPSInfo.hTTPSession.PacketData = packet;

                            PacketCaptured?.Invoke(packetInfo);
                        }
                        else if (IsSSHTraffic(tcpPacket))
                        {
                            PacketInfo packetInfo = CreateSSHPacketInfo(ipPacket, tcpPacket, rawPacket);

                            packetDetective.AnalyzeSSHPacket(packet, ref packetInfo);

                            PacketCaptured?.Invoke(packetInfo);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error processing packet: {e.Message}");
            }
        }

        private bool IsDNSTraffic(UdpPacket udpPacket)
        {
            return udpPacket.SourcePort == 53 || udpPacket.DestinationPort == 53;
        }

        private bool IsHttpTraffic(TcpPacket tcpPacket)
        {
            return tcpPacket.SourcePort == 80 || tcpPacket.DestinationPort == 80 ||
                   tcpPacket.SourcePort == 443 || tcpPacket.DestinationPort == 443;
        }

        private bool IsSSHTraffic(TcpPacket tcpPacket)
        {
            return tcpPacket.SourcePort == 22 || tcpPacket.DestinationPort == 22;
        }

        private PacketInfo CreateDNSPacketInfo(IPPacket ipPacket, UdpPacket udpPacket, RawCapture rawPacket)
        {
            PacketInfo packetInfo = new PacketInfo
            {
                Time = rawPacket.Timeval.Date,
                Length = rawPacket.Data.Length,
                Protocol = (udpPacket.SourcePort == 53 || udpPacket.DestinationPort == 53) ? "DNS" : "Unknown",
                Source = $"{ipPacket.SourceAddress}:{udpPacket.SourcePort}",
                Destination = $"{ipPacket.DestinationAddress}:{udpPacket.DestinationPort}"
            };

            return packetInfo;
        }

        private PacketInfo CreateHttpPacketInfo(IPPacket ipPacket, TcpPacket tcpPacket, RawCapture rawPacket)
        {
            PacketInfo packetInfo = new PacketInfo
            {
                Time = rawPacket.Timeval.Date,
                Length = rawPacket.Data.Length,
                Protocol = tcpPacket.SourcePort == 443 || tcpPacket.DestinationPort == 443 ? "HTTPS" : "HTTP",
                Source = $"{ipPacket.SourceAddress}:{tcpPacket.SourcePort}",
                Destination = $"{ipPacket.DestinationAddress}:{tcpPacket.DestinationPort}"
            };

            // If the destination port is 80, it's likely a request
            // If not, then a response (it's coming from the server)
            string direction = tcpPacket.DestinationPort == 80 ? "Request" : "Response";
            packetInfo.Info = $"{direction} | SEQ={tcpPacket.SequenceNumber} | ACK={tcpPacket.AcknowledgmentNumber} | Flags={tcpPacket.Flags}";

            return packetInfo;
        }

        private PacketInfo CreateSSHPacketInfo(IPPacket ipPacket, TcpPacket tcpPacket, RawCapture rawPacket)
        {
            PacketInfo packetInfo = new PacketInfo
            {
                Time = rawPacket.Timeval.Date,
                Length = rawPacket.Data.Length,
                Protocol = tcpPacket.SourcePort == 22 || tcpPacket.DestinationPort == 22 ? "SSHv2" : "Unknown",
                Source = $"{ipPacket.SourceAddress}:{tcpPacket.SourcePort}",
                Destination = $"{ipPacket.DestinationAddress}:{tcpPacket.DestinationPort}"
            };

            // If the destination port is 80, it's likely a request
            // If not, then a response (it's coming from the server)
            string direction = tcpPacket.DestinationPort == 80 ? "Request" : "Response";
            packetInfo.Info = $"{direction} | SEQ={tcpPacket.SequenceNumber} | ACK={tcpPacket.AcknowledgmentNumber} | Flags={tcpPacket.Flags}";

            return packetInfo;
        }
    }
}