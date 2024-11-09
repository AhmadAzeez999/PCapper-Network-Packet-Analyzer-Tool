using System;
using System.Collections.Generic;
using System.Text;
using PacketDotNet;
using PacketDotNet.Ieee80211;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Network_Packet_Analyzer_App.Core
{
    internal class NetworkAnalyzer
    {
        public NetworkAnalyzer()
        {
        }

        public void AnalyzeFile(string filePath)
        {
            CaptureFileReaderDevice device = new CaptureFileReaderDevice(filePath);

            device.Open();
            device.OnPacketArrival += DeviceOnPacketArrival;
            device.Capture();
        }

        private void DeviceOnPacketArrival(object s, PacketCapture e)
        {
            RawCapture rawPacket = e.GetPacket();
            Console.WriteLine(rawPacket);

            Packet packet = Packet.ParsePacket(LinkLayers.Ieee80211, rawPacket.Data);

            //Console.WriteLine(packet==null);

            //var ieePacket = packet.Extract<Ieee8021QPacket>();
            //Console.WriteLine(ieePacket);
        }
    }
}
