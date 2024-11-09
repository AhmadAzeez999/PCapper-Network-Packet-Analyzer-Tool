using Microsoft.Win32;
using Network_Packet_Analyzer_App.Core;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Network_Packet_Analyzer_App.MVVM.View
{
    /// <summary>
    /// Interaction logic for ConsoleView.xaml
    /// </summary>
    public partial class ConsoleView : UserControl
    {
        string currentFilePath = "";
        string currentFileExtension = "";

        NetworkAnalyzer networkAnalyzer;

        List<string> commandHistory = new List<string>();
        int commandHistoryIndex = 0;

        public ConsoleView()
        {
            InitializeComponent();

            networkAnalyzer = new NetworkAnalyzer();
        }

        // Use Loaded event for initializing the console output redirection
        private void UserControlLoaded(object sender, RoutedEventArgs e)
        {
            // Redirecting console output to the RichTextBox
            Console.SetOut(new TextBoxConsole(ConsoleOutput));
            Console.WriteLine("------------------------------------------------");
            Console.WriteLine("           PCapper's PCapping Console!          ");
            Console.WriteLine("------------------------------------------------");
            Console.WriteLine("Type 'help' for a list of all possible commands.");
        }

        public class TextBoxConsole : TextWriter
        {
            private readonly TextBox output;

            public TextBoxConsole(TextBox newOutput)
            {
                output = newOutput;
            }

            public override void Write(char value)
            {
                Application.Current.Dispatcher.Invoke(() => output.AppendText(value.ToString()));
            }

            public override void Write(string value)
            {
                Application.Current.Dispatcher.Invoke(() => output.AppendText(value));
            }

            public override void WriteLine(string value)
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    output.AppendText(value + "\n");
                    output.ScrollToEnd();
                });
            }

            public override Encoding Encoding => Encoding.UTF8;
        }

        private void LoadFileButtonClick(object sender, RoutedEventArgs e)
        {
            OpenFileExplorer();
        }

        private void OpenFileExplorer()
        {
            // Open file dialog to select a file
            OpenFileDialog openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
            {
                // Process the selected file (you can read its content or do any action here)
                currentFilePath = openFileDialog.FileName;
                Console.WriteLine($"Loaded file: {currentFilePath}");

                currentFileExtension = System.IO.Path.GetExtension(currentFilePath);

                if (currentFileExtension == ".pcap")
                {
                    Console.WriteLine($"{currentFileExtension} is supported.");
                }
                else
                {
                    Console.WriteLine($"{currentFileExtension} is not supported.");
                }
            }
        }

        private void InputBoxKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                string userInput = InputBox.Text;
                Console.WriteLine("> " + userInput);  // Redirecting input to console output
                InputBox.Clear(); // Clear the input box after sending input
                e.Handled = true; // Prevents any further processing of the Enter key

                commandHistoryIndex = 0;

                // Checking for commands
                if (userInput.Equals("help", StringComparison.OrdinalIgnoreCase))
                {
                    DisplayHelp();
                }
                else if (userInput.Equals("file", StringComparison.OrdinalIgnoreCase))
                {
                    if (currentFilePath == "")
                        Console.WriteLine($"No loaded file.");
                    else
                        Console.WriteLine($"Loaded file: {currentFilePath}");
                }
                else if (userInput.Equals("analyzefile", StringComparison.OrdinalIgnoreCase))
                {
                    if (currentFilePath == "")
                        Console.WriteLine($"No loaded file.");
                    else
                        networkAnalyzer.AnalyzeFile(currentFilePath);
                }
                else if (userInput.Equals("loadfile", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"Opening file explorer...");
                    OpenFileExplorer();
                }
                else if (userInput.Equals("clear", StringComparison.OrdinalIgnoreCase))
                {
                    ConsoleOutput.Clear();
                }
                else
                {
                    Console.WriteLine($"Unknown command: {userInput}");
                }

                commandHistory.Add(userInput);

                Console.WriteLine();
            }


            if (e.Key == Key.Up)
            {
                if (commandHistoryIndex < commandHistory.Count() && commandHistory.Count > 0)
                {
                    InputBox.Text = commandHistory[commandHistory.Count() - ++commandHistoryIndex];
                }
            }

            if (e.Key == Key.Down)
            {
                if (commandHistoryIndex > 1 && commandHistory.Count > 0)
                {
                    InputBox.Text = commandHistory[commandHistory.Count() - --commandHistoryIndex];
                }
            }
        }

        private void DisplayHelp()
        {
            Console.WriteLine("\nCommands:");
            Console.WriteLine("- file: Shows the loaded file path.");
            Console.WriteLine("- analyzefile: Analyzes packet file.");
            Console.WriteLine("- loadfile: Opens a file explorer window for loading files.");
            Console.WriteLine("- clear: To erase all text.");
        }
    }
}
