using System;
using System.Net;
using System.Windows.Forms;

namespace Sniffer_v3
{
    public partial class Form4 : Form
    {

        public Form4(string enc, string time, int check, IPAddress ip, int port, string path)
        {
            InitializeComponent();
            comboBox2.Text = enc;
            comboBox3.Text = time;
            comboBox4.Text = Convert.ToString(check);
            textBox1.Text = Convert.ToString(ip);
            textBox2.Text = Convert.ToString(port);
            textBox3.Text = Convert.ToString(path);
        }
        // Присваиваем новые значения
        private void button1_Click(object sender, EventArgs e)
        {
            Form1 own = this.Owner as Form1;
            own.enc = comboBox2.Text;
            own.time_format = comboBox3.Text;
            own.check = Convert.ToInt32(comboBox4.Text);
            own.ip = IPAddress.Parse(textBox1.Text);
            own.port = Convert.ToInt32(textBox2.Text);
            own.path = textBox3.Text;
            own.message = richTextBox1.Text;
            this.Close();
        }

        private void Form4_Load(object sender, EventArgs e)
        {

        }
    }
}
