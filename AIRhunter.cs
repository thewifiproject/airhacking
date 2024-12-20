using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Windows.Forms;
using PacketDotNet;
using SharpPcap;

namespace WifiNetworkAnalyzer
{
    public partial class MainForm : Form
    {
        private IList<ICaptureDevice> devices;
        private ICaptureDevice selectedDevice;
        private Thread captureThread;
        private bool capturing;
        private Dictionary<string, NetworkInfo> networks;

        public MainForm()
        {
            InitializeComponent();
            networks = new Dictionary<string, NetworkInfo>();
        }

        private void MainForm_Load(object sender, EventArgs e)
        {
            devices = CaptureDeviceList.Instance;
            foreach (var device in devices)
            {
                comboBoxAdapters.Items.Add(device.Description);
            }
        }

        private void buttonStart_Click(object sender, EventArgs e)
        {
            if (comboBoxAdapters.SelectedIndex < 0)
            {
                MessageBox.Show("Please select a Wi-Fi adapter.");
                return;
            }

            selectedDevice = devices[comboBoxAdapters.SelectedIndex];
            selectedDevice.OnPacketArrival += Device_OnPacketArrival;
            selectedDevice.Open(DeviceMode.Promiscuous, 1000);

            capturing = true;
            captureThread = new Thread(CapturePackets);
            captureThread.Start();

            buttonStart.Enabled = false;
            buttonStop.Enabled = true;
        }

        private void buttonStop_Click(object sender, EventArgs e)
        {
            StopCapture();
        }

        private void CapturePackets()
        {
            selectedDevice.Capture();
        }

        private void Device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var radioPacket = packet.Extract<RadioPacket>();
            if (radioPacket == null) return;

            var essid = radioPacket.ESSID;
            var bssid = radioPacket.BSSID;
            var power = radioPacket.SignalStrength;
            var encryption = radioPacket.EncryptionType;

            if (!networks.ContainsKey(bssid))
            {
                networks[bssid] = new NetworkInfo { BSSID = bssid, ESSID = essid, Power = power, Encryption = encryption, Note = "" };
            }
            else
            {
                networks[bssid].Power = power;
            }

            // Check for EAPOL handshake
            if (radioPacket.IsEapol)
            {
                networks[bssid].Note = "HANDSHAKE!";
            }

            UpdateGridView();
        }

        private void UpdateGridView()
        {
            if (dataGridView.InvokeRequired)
            {
                dataGridView.Invoke(new MethodInvoker(UpdateGridView));
            }
            else
            {
                dataGridView.Rows.Clear();
                foreach (var network in networks.Values)
                {
                    dataGridView.Rows.Add(network.BSSID, network.ESSID, network.Power, network.Encryption, network.Note);
                }
            }
        }

        private void StopCapture()
        {
            if (selectedDevice != null && capturing)
            {
                capturing = false;
                selectedDevice.Close();
                captureThread.Join();

                buttonStart.Enabled = true;
                buttonStop.Enabled = false;
            }
        }

        private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            StopCapture();
        }

        private class NetworkInfo
        {
            public string BSSID { get; set; }
            public string ESSID { get; set; }
            public string Power { get; set; }
            public string Encryption { get; set; }
            public string Note { get; set; }
        }
    }
}
