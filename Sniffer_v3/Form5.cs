using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;

namespace Sniffer_v3
{
    public partial class Form5 : Form
    {
        List<IPAddress> ip_list = new List<IPAddress>();
        public Form5()
        {
            InitializeComponent();
            richTextBox1.Text += "Searching";
        }

        public void Add(IPAddress ip)
        {
            ip_list.Add(ip);
            richTextBox1.Text += ".";
        }

        public void Ping()
        {
            richTextBox1.Text += "\n";
            richTextBox1.Text += "Searching is done. Start pinging: " + "\n";
            Ping pingsender = new Ping();
            PingReply reply;
            foreach (IPAddress ip in ip_list)
            {
                reply = pingsender.Send(ip);
                richTextBox1.Text += Convert.ToString("IP  " + Convert.ToString(ip) + "   " + reply.Status.ToString() + "\n");

            }
            richTextBox1.Text += "Pinging is done. " + "\n";
        }
    }
}
