using System;
using System.Windows.Forms;
using System.Net;
using SharpPcap;
using PacketDotNet;
using System.Text;
using System.Collections.Generic;
using System.Threading;
using System.Timers;
using System.Drawing;
using System.Net.Sockets;
using System.IO;
namespace Sniffer_v3
{

    public partial class Form1 : Form
    {
        // список устройств
        CaptureDeviceList list;
        ICaptureDevice device;
        // статистика
        ICaptureStatistics s;
        // ip-адреса для пинга и свои ip-адреса
        List<IPAddress> ip_list;
        List<IPAddress> my_ips;
        // флаг начала прослушки
        bool start = false;
        // кодировка для данных в пакете
        public string enc = "UTF-8";
        // формат времени поимки пакета
        public string time_format = "hh.mm.ss.ffffff";
        // время, отводимое для сбора ip-адресов в ip_list
        public int check = 10;
        // ip-адрес, на который нужно отправлять или прослушивать
        public IPAddress ip = IPAddress.Parse("178.204.110.206");
        // порт, на который нужно отправлять
        public int port = 8888;
        // количество пойманных пакетов
        int catched = 0;
        // путь записи
        public string path = "test.txt";
        // сообщение
        public string message;
        Form5 f;
        Mutex m = new Mutex();
        System.Timers.Timer t;
        public Form1()
        {
            InitializeComponent();
            f = new Form5();
            ip_list = new List<IPAddress>();
            my_ips = new List<IPAddress>();
            // вывод всех имеющихся устройств
            list = CaptureDeviceList.Instance;
            foreach (ICaptureDevice i in list)
            {
                string name = i.Friendly();
                name = name.Replace("interface:", "");
                if (name !="")
                comboBox1.Items.Add(name);
            }
            comboBox1.Text = comboBox1.Items[0].ToString();
            label2.BringToFront();
            label3.BringToFront();
            label4.BringToFront();
            label5.BringToFront();
            button1.FlatAppearance.BorderSize = 2;
        }
        // старт
        private void button1_Click(object sender, EventArgs e)
        {
            if (!start)
            {
                button1.Text = "Stop";
                button12.Visible = false;
                button1.FlatAppearance.BorderColor = Color.Red;
                catched = 0;
                start = true;
                // выбор устройств для прослушки        
                device = list[comboBox1.SelectedIndex];
                // событие, происходящее при поимке пакета
                device.OnPacketArrival += new PacketArrivalEventHandler(capture_event);
                // установление Promiscuous mode
                device.Open(DeviceMode.Promiscuous);
                // захват
                device.StartCapture();
            }
            else
            {
                button1.Text = "Start";
                button12.Visible = true;
                button1.FlatAppearance.BorderColor = Color.DimGray;
                device.StopCapture();
                start = false;
            }
        }
        // Фильтр
        private void button2_Click(object sender, EventArgs e)
        {
            start = true;
            button1.Text = "Stop";
            button12.Visible = false;
            button1.FlatAppearance.BorderColor = System.Drawing.Color.Red;
            device = list[comboBox1.SelectedIndex];
            device.OnPacketArrival += new PacketArrivalEventHandler(capture_event6);
            device.Open(DeviceMode.Promiscuous);
            device.StartCapture();
        }

        private void Form1_FormClosed(object sender, FormClosedEventArgs e)
        {
            if (start){
                device.StopCapture();
                device.Close();
            }
        }

        // Информация о пакетах
        private void button3_Click(object sender, EventArgs e)
        {
            if (dataGridView1.SelectedRows.Count == 0)
            {
                MessageBox.Show("Выберите пакеты, которые хотите просмотреть");
            }
            for(int i = 0; i < dataGridView1.SelectedRows.Count; i++)
            {
                DataGridViewRow row = dataGridView1.SelectedRows[i];
                object[] data = new object[] { row.Cells[0].Value, row.Cells[1].Value, row.Cells[2].Value,
                                               row.Cells[3].Value, row.Cells[4].Value, row.Cells[5].Value};
                Form2 f = new Form2(data, enc);
                f.Show();
            }

        }
        // Информация о сетевых интерфейсах
        private void button4_Click(object sender, EventArgs e)
        {
            Form3 f = new Form3("Devices");
            f.Show();
        }
        // Пинг
        private void button5_Click(object sender, EventArgs e)
        {
            f.Show();
            start = true;
            button1.Text = "Stop";
            button12.Visible = false;
            button1.FlatAppearance.BorderColor = System.Drawing.Color.Red;       
            device = list[comboBox1.SelectedIndex];
            device.OnPacketArrival += new PacketArrivalEventHandler(capture_event3);
            device.Open(DeviceMode.Promiscuous);
            t = new System.Timers.Timer(check * 1000);
            t.Elapsed += OnTimedEvent;
            t.Enabled = true;
            t.Start();
            device.StartCapture();
        }
        // Событие, вызываемое после окончания времени таймера (для ping)
        private  void OnTimedEvent(Object source, ElapsedEventArgs e)
        {
            device.StopCapture();
            start = false;
            f.Ping();
            t.Stop();
        }
        // Сохранение содержимого
        private void button6_Click(object sender, EventArgs e)
        {
            StreamWriter sw = new StreamWriter(path, false, Encoding.Default);
            sw.Write(Convert.ToString(dataGridView1.SelectedRows[0].Cells[5].Value));
            sw.Close();            
        }
        // Прослушка указанного в настройках ip
        private void button7_Click(object sender, EventArgs e)
        {
                start = true;
                button1.Text = "Stop";
                button12.Visible = false;
                button1.FlatAppearance.BorderColor = System.Drawing.Color.Red;
                catched = 0;      
                device = list[comboBox1.SelectedIndex];
                device.OnPacketArrival += new PacketArrivalEventHandler(capture_event2);
                device.Open(DeviceMode.Promiscuous);
                device.StartCapture();
        }
        // Справка и инструкции
        private void button10_Click(object sender, EventArgs e)
        {
            Form3 f = new Form3("Instruction");
            f.Show();
        }
        // Настройки параметров
        private void button11_Click(object sender, EventArgs e){
            Form4 f = new Form4(enc,time_format,check,ip,port,path);
            f.Owner = this;
            f.Show();
        }
        // Send
        private void button9_Click(object sender, EventArgs e){
            if (!start)
            {
                start = true;
                button1.Text = "Stop";
                button12.Visible = false;
                button1.FlatAppearance.BorderColor = System.Drawing.Color.Red;
                catched = 0;      
                device = list[comboBox1.SelectedIndex];
                device.OnPacketArrival += new PacketArrivalEventHandler(capture_event5);
                device.Open(DeviceMode.Promiscuous);
                device.StartCapture();

            }
        }
        // Тест
        private void button8_Click(object sender, EventArgs e){
            if (!start)
            {
                start = true;
                button1.Text = "Stop";
                button12.Visible = false;
                button1.FlatAppearance.BorderColor = System.Drawing.Color.Red;
                catched = 0;       
                device = list[comboBox1.SelectedIndex];
                device.OnPacketArrival += new PacketArrivalEventHandler(capture_event4);
                device.Open(DeviceMode.Promiscuous);
                t = new System.Timers.Timer(1000);
                t.Elapsed += OnTimedEvent2;
                t.Enabled = true;
                t.Start();
                device.StartCapture();
            }
        }
        // событие, вызываемое после окончания времени таймера (для ping)
        private void OnTimedEvent2(Object source, ElapsedEventArgs e)
        {
            UdpClient udp = new UdpClient();
            byte[] data = Encoding.UTF8.GetBytes("This is my UDP test message!");
            udp.Send(data, data.Length, ip.ToString(), 8888);

        }
        // событие, вызываемое при захвате пакета
        private void capture_event(object sender, CaptureEventArgs e)
        {
            m.WaitOne();
            Packet p = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            IpPacket ip = (IpPacket)p.Extract(typeof(IpPacket));
            TcpPacket tcp = (TcpPacket)p.Extract(typeof(TcpPacket));
            UdpPacket udp = (UdpPacket)p.Extract(typeof(UdpPacket));
            s = device.Statistics;
            if (udp != null)
            {
                string time = DateTime.Now.ToString(time_format);
                int length = e.Packet.Data.Length;
                string source = ip.SourceAddress.ToString();
                string destinition = ip.DestinationAddress.ToString();
                var protocol = ip.Protocol;
                string data = p.PrintHex(enc);
                object[] row = new object[] { time, length, source, destinition, protocol, data };
                dataGridView1.Rows.Add(row);
                if (my_ips.Contains(ip.SourceAddress) || my_ips.Contains(ip.DestinationAddress))
                {
                    dataGridView1.Rows[catched].DefaultCellStyle.BackColor = Color.Pink;
                }
                catched++;
                label2.Text = "";
                label3.Text = "";
                label4.Text = "";
            }
            label2.Text = "Received Packets: " + Convert.ToString(s.ReceivedPackets);
            label3.Text = "Dropped Packets: " + Convert.ToString(s.DroppedPackets);
            label4.Text = "Interface Dropped Packets: " + Convert.ToString(s.InterfaceDroppedPackets);
            label6.Text = "Catched Packets: " + Convert.ToString(catched);
            m.ReleaseMutex();
        }
        // listen-event
        private void capture_event2(object sender, CaptureEventArgs e)
        {
            Packet p = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            IpPacket ip = (IpPacket)p.Extract(typeof(IpPacket));
            TcpPacket tcp = (TcpPacket)p.Extract(typeof(TcpPacket));
            s = device.Statistics;
            if (tcp != null && ip != null && (ip.DestinationAddress.ToString() == this.ip.ToString() || ip.SourceAddress.ToString() == this.ip.ToString()))
            {
                m.WaitOne();
                string time = DateTime.Now.ToString(time_format);
                int length = e.Packet.Data.Length;
                string source = ip.SourceAddress.ToString();
                string destinition = ip.DestinationAddress.ToString();
                var protocol = ip.Protocol;
                string data = p.PrintHex(enc);
                object[] row = new object[] { time, length, source, destinition, protocol, data };
                dataGridView1.Rows.Add(row);
                catched++;
                label2.Text = "";
                label3.Text = "";
                label4.Text = "";
                m.ReleaseMutex();
            }
            label2.Text = "Received Packets: " + Convert.ToString(s.ReceivedPackets);
            label3.Text = "Dropped Packets: " + Convert.ToString(s.DroppedPackets);
            label4.Text = "Interface Dropped Packets: " + Convert.ToString(s.InterfaceDroppedPackets);
            label6.Text = "Catched Packets: " + Convert.ToString(catched);
        }
        // ping-event
        private void capture_event3(object sender, CaptureEventArgs e)
        {
            Packet p = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            IpPacket ip = (IpPacket)p.Extract(typeof(IpPacket));
            UdpPacket udp = (UdpPacket)p.Extract(typeof(UdpPacket));
            if (udp != null)
            {
                IPAddress src = ip.SourceAddress;
                IPAddress dest = ip.DestinationAddress;
                if (!ip_list.Contains(src))
                {
                    ip_list.Add(src);
                    f.Add(src);
                }
                else if (!ip_list.Contains(dest))
                {
                    ip_list.Add(dest);
                    f.Add(dest);
                }
            }
         }
        // Test
        private void capture_event4(object sender, CaptureEventArgs e)
        {
            m.WaitOne();
            Packet p = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            IpPacket ip = (IpPacket)p.Extract(typeof(IpPacket));
            UdpPacket udp = (UdpPacket)p.Extract(typeof(UdpPacket));
            if (udp!= null)
            {
                string time = DateTime.Now.ToString(time_format);
                int length = e.Packet.Data.Length;
                int offset = ip.HeaderLength;
                string source = ip.SourceAddress.ToString();
                string destinition = ip.DestinationAddress.ToString();
                var protocol = ip.Protocol;
                string data = p.PrintHex(enc);
                object[] row = new object[] { time, length, source, destinition, protocol, data };
                dataGridView1.Rows.Add(row);
                if (destinition == this.ip.ToString())
                {
                    dataGridView1.Rows[catched].DefaultCellStyle.BackColor = Color.Pink;
                }
                catched++;
            }
            m.ReleaseMutex();
        }
        // Send
        private void capture_event5(object sender, CaptureEventArgs e)
        {
            Packet p = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            IpPacket ip = (IpPacket)p.Extract(typeof(IpPacket));
            UdpPacket udpp = (UdpPacket)p.Extract(typeof(UdpPacket));
            s = device.Statistics;
            if (udpp != null)
            {
                m.WaitOne();
                string time = DateTime.Now.ToString(time_format);
                int length = e.Packet.Data.Length;
                int offset = ip.HeaderLength;
                string source = ip.SourceAddress.ToString();
                string destinition = ip.DestinationAddress.ToString();
                var protocol = ip.Protocol;
                string data = p.GetData(offset);
                object[] row = new object[] { time, length, source, destinition, protocol, data };
                dataGridView1.Rows.Add(row);
                if (destinition == this.ip.ToString())
                {
                    dataGridView1.Rows[catched].DefaultCellStyle.BackColor = Color.Pink;
                }
                UdpClient udp = new UdpClient();
                byte[] payload = Encoding.UTF8.GetBytes(data);
                udp.Send(payload, payload.Length, this.ip.ToString(), 8888);
                catched++;
                label2.Text = "";
                label3.Text = "";
                label4.Text = "";
                m.ReleaseMutex();
            }
            label2.Text = "Received Packets: " + Convert.ToString(s.ReceivedPackets);
            label3.Text = "Dropped Packets: " + Convert.ToString(s.DroppedPackets);
            label4.Text = "Interface Dropped Packets: " + Convert.ToString(s.InterfaceDroppedPackets);
            label6.Text = "Catched Packets: " + Convert.ToString(catched);
        }
        // filter-event
        private void capture_event6(object sender, CaptureEventArgs e)
        {
            Packet p = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            IpPacket ip = (IpPacket)p.Extract(typeof(IpPacket));
            TcpPacket tcp = (TcpPacket)p.Extract(typeof(TcpPacket));
            UdpPacket udp = (UdpPacket)p.Extract(typeof(UdpPacket));
            s = device.Statistics;
            if (udp != null)
            {
                m.WaitOne();
                string time = DateTime.Now.ToString(time_format);
                int length = e.Packet.Data.Length;
                string source = ip.SourceAddress.ToString();
                string destinition = ip.DestinationAddress.ToString();
                var protocol = ip.Protocol;
                string data = p.PrintHex(enc);
                string mes = p.GetData(ip.HeaderLength);
                if (mes.Contains(message))
                {
                    object[] row = new object[] { time, length, source, destinition, protocol, data };
                    dataGridView1.Rows.Add(row);
                    catched++;
                }
                label2.Text = "";
                label3.Text = "";
                label4.Text = "";
                m.ReleaseMutex();
            }
            label2.Text = "Received Packets: " + Convert.ToString(s.ReceivedPackets);
            label3.Text = "Dropped Packets: " + Convert.ToString(s.DroppedPackets);
            label4.Text = "Interface Dropped Packets: " + Convert.ToString(s.InterfaceDroppedPackets);
            label6.Text = "Catched Packets: " + Convert.ToString(catched);
        }
        private void label5_Click(object sender, EventArgs e)
        {
            Form6 f = new Form6(dataGridView1);
            f.Show();
            if (start)
            {
                button1.Text = "Start";
                button12.Visible = false;
                button1.FlatAppearance.BorderColor = Color.DimGray;
                device.StopCapture();
                start = false;
            }
        }

        private void label5_MouseEnter(object sender, EventArgs e)
        {
            label5.ForeColor = Color.Maroon;
        }

        private void label5_MouseLeave(object sender, EventArgs e)
        {
            label5.ForeColor = Color.Black;
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void button12_Click(object sender, EventArgs e)
        {
            dataGridView1.Rows.Clear();
        }

        private void button12_MouseEnter(object sender, EventArgs e)
        {
            ToolTip ToolTip1 = new ToolTip();
            int VisibleTime = 1000;
            Button TB = (Button)sender;
            ToolTip1.Show("Удалить текст", TB, 30, 0, VisibleTime);
        }

        private void dataGridView1_CellContentClick(object sender, DataGridViewCellEventArgs e)
        {

        }
    }

}
