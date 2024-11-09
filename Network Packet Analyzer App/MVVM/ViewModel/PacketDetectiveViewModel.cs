using Microsoft.Win32; // Make sure to include this namespace
using Network_Packet_Analyzer_App.Core;
using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Media;
using System.Threading.Tasks;
using System.Windows.Input;

namespace Network_Packet_Analyzer_App.MVVM.ViewModel
{
    internal class PacketDetectiveViewModel : INotifyPropertyChanged
    {
        private string filePath;
        public string FilePath
        {
            get => filePath;
            set
            {
                filePath = value;
                OnPropertyChanged(nameof(FilePath));
            }
        }


        private string scanType;

        public string ScanType
        {
            get => scanType;
            set
            {
                scanType = value;
                OnPropertyChanged(nameof(ScanType));
            }
        }

        public ObservableCollection<string> ScanTypeOptions { get; } = new ObservableCollection<string>
        {
            "DNS Tunneling",
            "HTTPS Tunneling",
            "SSH Tunneling",
            "General DPI"
        };

        public ICommand BrowseFileCommand { get; }
        public ICommand ScanFileCommand { get; }
        public ICommand ClearScanCommand { get; }

        OfflinePacketDetective detective = new OfflinePacketDetective("d9bfc00fb1620e04e6b5e3fac14a7260116ab1a0e21aca62c60056dc2a33b714");
        DeepPacketInspector dpi;

        public string ScanResults {  get; set; }
        public string AlertMessage { get; set; }

        // Implementing INotifyPropertyChanged members
        public event PropertyChangedEventHandler PropertyChanged;

        private int messageIndex = 0;

        public PacketDetectiveViewModel()
        {
            dpi = new DeepPacketInspector();

            BrowseFileCommand = new RelayCommand(o =>
            {
                BrowseFile();
            });

            ScanFileCommand = new RelayCommand(o =>
            {
                ScanFile();
            });

            ClearScanCommand = new RelayCommand(o => ClearScanResults());
        }

        private void BrowseFile()
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Filter = "PCAP files (*.pcap)|*.pcap|PCAPNG files (*.pcapng)|*.pcapng",
                Title = "Select a PCAP File"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                FilePath = openFileDialog.FileName; // Setting the selected file path
            }
        }

        private void ScanFile()
        {
            switch(ScanType)
            {
                case "DNS Tunneling":
                    ScanFileForDNS();
                    break;
                case "HTTPS Tunneling":
                    ScanFileForHTTPS();
                    break;
                case "SSH Tunneling":
                    ScanFileForSSH();
                    break;
                case "General DPI":
                    ScanFileWithDPI();
                    break;
                default:
                    break;
            }
        }

        private async void ScanFileForDNS()
        {

            detective.PacketScanned += PacketScanMessage;
            await detective.AnalyzePcapFile(FilePath);

        }

        private async void ScanFileForHTTPS()
        {

            detective.PacketScanned += PacketScanMessage;
            await detective.AnalyzePcapFileForHTTPS(FilePath);

        }

        private async void ScanFileForSSH()
        {

            detective.PacketScanned += PacketScanMessage;
            await detective.AnalyzePcapFileForSSH(FilePath);
        }

        private async void ScanFileWithDPI()
        {
            dpi.PacketScanned += PacketScanMessage;
            await Task.Run(() => dpi.AnalyzeFile(FilePath));

        }

        protected void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        private void PacketScanMessage(string message)
        {
            message = (message == "") ? "" : ++messageIndex + ". " + message;
            ScanResults += message;
            
            if (ScanResults == "")
            {
                // AlertMessage = "No potential malicious packets found.";
            }
            else
            {
                // AlertMessage = "Malicious packets found!";
                // PlayMusic(@"C:\Users\abios\OneDrive\Documents\C# Apps\Network Packet Analyzer App\Network Packet Analyzer App\Audio\Among Us Impostor Sound Effect.wav");
            }

            OnPropertyChanged(nameof(ScanResults));

            if (message.Contains("malware"))
            {
                // AlertMessage = $"Potential malware detected!\n{message}";
                OnPropertyChanged(nameof(AlertMessage));
            }
        }

        public void ClearScanResults()
        {
            ScanResults = "";
            messageIndex = 0;
            OnPropertyChanged(nameof(ScanResults));
        }

        public static void PlayMusic(string filepath)
        {
            SoundPlayer player = new SoundPlayer();
            player.SoundLocation = filepath;
            player.Play();

        }
    }

}
