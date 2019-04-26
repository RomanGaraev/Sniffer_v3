using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Sniffer_v3
{
    public partial class Form2 : Form
    {
        public Form2(object[] row, string enc)
        {
            InitializeComponent();
            string time = Convert.ToString(row[0]);
            string length = Convert.ToString(row[1]);
            string source = Convert.ToString(row[2]);
            string destinition = Convert.ToString(row[3]);
            string protocol = Convert.ToString(row[4]);
            string data = Convert.ToString(row[5]);
            richTextBox1.Text += "Time: " + time + "\n";
            richTextBox1.Text += "Length: " + length + "\n";
            richTextBox1.Text += "Source ip: " + source + "\n";
            richTextBox1.Text += "Destinition ip: " + destinition + "\n";
            richTextBox1.Text += "Protocol: " + protocol + "\n";
            richTextBox1.Text += "Data: " + data + "\n";
        }
    }
}
