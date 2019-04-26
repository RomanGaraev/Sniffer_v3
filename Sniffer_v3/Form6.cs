using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Windows.Forms.DataVisualization.Charting;
namespace Sniffer_v3
{
    public partial class Form6 : Form
    {
    // Словарь из ip и стека времени, в которое с этого ip были отправлены пакеты
    Dictionary<string,Stack<string>> map = new Dictionary<string, Stack<string>>();
    public Form6(DataGridView dgw)
        {
            InitializeComponent();
            // Добавляем пакеты в словарь
            for (int i = 0; i < dgw.RowCount; i++)
            {
                AddPacket(Convert.ToString(dgw.Rows[i].Cells[2].Value), Convert.ToString(dgw.Rows[i].Cells[0].Value));
            }
            int j = 1;
            // Строим график
            foreach (KeyValuePair<string, Stack<string>> pair in map)
            {
                if (pair.Key.ToString() != "")
                {
                    string ip = pair.Key.ToString();
                    chart1.Series.Add(ip);
                    chart1.Series[ip].ChartType = SeriesChartType.Line;
                    j += 1;
                    int[] time = new int[24];
                    for (int i = 0; i < 24; i++) { time[i] = 0; }
                    // Добавляем количество пакетов в часы
                    foreach (string str in pair.Value)
                    {
                        time[Convert.ToInt32(string.Concat(str[0], str[1]))] += 1;
                    }
                    for (int k = 0; k < 24; k++)
                    {
                        chart1.Series[ip].Points.AddXY(k, time[k]);
                    }
                    
                }
            }
        }

        private void AddPacket(string address, string time)
        {
            if (!map.ContainsKey(address))
            {
                Stack<string> s = new Stack<string>();
                map.Add(address, s);
            }
                map[address].Push(time);
        }
    }
}
