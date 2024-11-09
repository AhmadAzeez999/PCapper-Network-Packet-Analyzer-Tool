using Network_Packet_Analyzer_App.Core;
using Network_Packet_Analyzer_App.MVVM.Model;
using PacketDotNet;
using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;

namespace Network_Packet_Analyzer_App.MVVM.ViewModel
{
    internal class MainViewModel : ObservableObject
    {
        public RelayCommand DashboardViewCommand { get; set; }
        public RelayCommand PacketDetectiveViewCommand { get; set; }
        public RelayCommand ConsoleViewCommand { get; set; }
        public RelayCommand AboutViewCommand { get; set; }
        public RelayCommand CloseAppCommand { get; set; }
        public RelayCommand ResizeAppCommand { get; set; }
        public RelayCommand MinimizeAppCommand { get; set; }
        public RelayCommand StopPacketCaptureCommand { get; set; }

        public DashboardViewModel DashboardVM {  get; set; }
        public PacketDetectiveViewModel PacketDetectiveVM { get; set; }
        public ConsoleViewModel ConsoleVM { get; set; }
        public AboutViewModel AboutVM { get; set; }

        private object currentView;

        public object CurrentView
        {
            get { return currentView; }
            set
            {
                currentView = value;
                OnPropertyChanged();
            }
        }

        LivePacketCapture capture = new LivePacketCapture();

        public bool captureStarted = false;

        private string selectedDevice;
        public string SelectedDevice
        {
            get => selectedDevice;
            set
            {
                selectedDevice = value;
                OnPropertyChanged(nameof(SelectedDevice));
            }
        }

        public Visibility selectMenuVisibility;
        public Visibility stopButtonVisibility;
        public Visibility SelectMenuVisibility
        {
            get => selectMenuVisibility;
            set
            {
                selectMenuVisibility = value;
                OnPropertyChanged(nameof(SelectMenuVisibility));
            }
        }
        public Visibility StopButtonVisibility
        {
            get => stopButtonVisibility;
            set
            {
                stopButtonVisibility = value;
                OnPropertyChanged(nameof(StopButtonVisibility));
            }
        }

        public ObservableCollection<AvailableDevice> AvailableDevices { get; set; }

        public ICommand SelectDeviceCommand { get; }

        public MainViewModel()
        {
            AvailableDevices = capture.ListAvailableDevices();
            SelectDeviceCommand = new RelayCommand(ExecuteSelectedDevice);
            SelectMenuVisibility = Visibility.Visible;
            StopButtonVisibility = Visibility.Hidden;

            DashboardVM = new DashboardViewModel();
            PacketDetectiveVM = new PacketDetectiveViewModel();
            ConsoleVM = new ConsoleViewModel();
            AboutVM = new AboutViewModel();

            CurrentView = DashboardVM;

            DashboardViewCommand = new RelayCommand(o =>
            {
                CurrentView = DashboardVM;
            });

            PacketDetectiveViewCommand = new RelayCommand(o =>
            {
                CurrentView = PacketDetectiveVM;
            });

            ConsoleViewCommand = new RelayCommand(o =>
            {
                CurrentView = ConsoleVM;
            });

            AboutViewCommand = new RelayCommand(o =>
            {
                CurrentView = AboutVM;
            });

            CloseAppCommand = new RelayCommand(o =>
            {
                Application.Current.Shutdown();
            });

            ResizeAppCommand = new RelayCommand(o =>
            {
                Window mainWindow = Application.Current.MainWindow;

                if (mainWindow.WindowState == WindowState.Maximized)
                {
                    mainWindow.WindowState = WindowState.Normal;
                }
                else
                {
                    mainWindow.WindowState = WindowState.Maximized;
                }
            });

            MinimizeAppCommand = new RelayCommand(o =>
            {
                Application.Current.MainWindow.WindowState = WindowState.Minimized;
            });

            StopPacketCaptureCommand = new RelayCommand(async o =>
            {
                capture.StopCapture();
                captureStarted = false;
                SelectMenuVisibility = Visibility.Visible;
                StopButtonVisibility = Visibility.Hidden;
                SelectedDevice = "";
            });

            capture.PacketCaptured += OnPacketCaptured;
        }

        public async void OnPacketCaptured(PacketInfo packetInfo)
        {
            // To run it on a different thread
            await Task.Run(() => 
            {
                DashboardVM.AddToPacketList(packetInfo);
                //Console.WriteLine(DashboardVM.Packets.Count);

                if (packetInfo.DNSQueryInfo != null)
                {
                    DashboardVM.AddToSuspiciousPacketList(packetInfo);
                }

                if (packetInfo.HTTPSInfo != null && packetInfo.HTTPSInfo.potentialHTTPSTunneling)
                {
                    DashboardVM.AddToSuspiciousHttpsPacketList(packetInfo);
                }

                if (packetInfo.SSHInfo != null && packetInfo.SSHInfo.PotentialSSHTunneling)
                {
                    DashboardVM.AddToSuspiciousSSHPacketList(packetInfo);
                }

                if (packetInfo.containsSuspiciousUrl)
                {
                    DashboardVM.AddToSuspiciousUrlList(packetInfo);
                }
            });
        }

        private async void ExecuteSelectedDevice(object parameter)
        {
            if (captureStarted == false)
            {
                //Console.WriteLine("Selected Num: " + parameter);
                capture.SelectDevice((int) parameter);
                SelectedDevice = capture.GetDevice((int)parameter).Description;
                await capture.StartCapture();
                captureStarted = true;
                SelectMenuVisibility = Visibility.Hidden;
                StopButtonVisibility = Visibility.Visible;
            }
        }
    }
}
