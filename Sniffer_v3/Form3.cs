using System;
using System.Windows.Forms;
using SharpPcap;
using System.IO;
using System.Text;

namespace Sniffer_v3
{
    public partial class Form3 : Form
    {
        public Form3(string type)
        {
            InitializeComponent();
            this.Text = type;
            if (type == "Devices")
            {
                CaptureDeviceList list = CaptureDeviceList.Instance;
                foreach (ICaptureDevice i in list)
                {
                    richTextBox1.Text += Convert.ToString(i);
                }
            }
            else if (type == "Instruction")
            {
                string[] lines = File.ReadAllLines(@"Instruction.txt", Encoding.GetEncoding(1251));
                foreach (string inst in lines)
                {
                    richTextBox1.Text += inst;
                    richTextBox1.Text += "\n";
                }
            }
        }
    }
}
