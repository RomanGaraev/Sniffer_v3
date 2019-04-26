// Decompiled with JetBrains decompiler
// Type: PacketDotNet.Packet
// Assembly: PacketDotNet, Version=0.13.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 29B26C27-D25F-4074-A144-2676F3AFBE7D
// Assembly location: C:\Users\demo8\OneDrive\Документы\Visual Studio 2015\Projects\Sniffer_v3\SharpPcap-4.2.0\Release\PacketDotNet.dll

using PacketDotNet.Ieee80211;
using PacketDotNet.Utils;
using System;
using System.IO;
using System.Text;

namespace PacketDotNet
{
  /// <summary>
  /// Base class for all packet types.
  /// Defines helper methods and accessors for the architecture that underlies how
  /// packets interact and store their data.
  /// </summary>
  public abstract class Packet
  {
    /// <summary>Used internally when building new packet dissectors</summary>
    protected PacketOrByteArraySegment payloadPacketOrData = new PacketOrByteArraySegment();
    private static readonly ILogInactive log;
    /// <summary>Used internally when building new packet dissectors</summary>
    protected ByteArraySegment header;
    /// <summary>
    /// The parent packet. Accessible via the 'ParentPacket' property
    /// </summary>
    private Packet parentPacket;

    /// <summary>
    /// Gets the total length of the packet.
    /// Recursively finds the length of this packet and all of the packets
    /// encapsulated by this packet
    /// </summary>
    /// <value>The total length of the packet.</value>
    protected int TotalPacketLength
    {
      get
      {
        int num = 0 + this.header.Length;
        if (this.payloadPacketOrData.Type == PayloadType.Bytes)
          num += this.payloadPacketOrData.TheByteArraySegment.Length;
        else if (this.payloadPacketOrData.Type == PayloadType.Packet)
          num += this.payloadPacketOrData.ThePacket.TotalPacketLength;
        return num;
      }
    }

    /// <value>
    /// Returns true if we already have a contiguous byte[] in either
    /// of these conditions:
    /// - This packet's header byte[] and payload byte[] are the same instance
    /// or
    /// - This packet's header byte[] and this packet's payload packet
    /// are the same instance and the offsets indicate that the bytes
    /// are contiguous
    /// </value>
    protected bool SharesMemoryWithSubPackets
    {
      get
      {
        switch (this.payloadPacketOrData.Type)
        {
          case PayloadType.Packet:
            if (this.header.Bytes == this.payloadPacketOrData.ThePacket.header.Bytes && this.header.Offset + this.header.Length == this.payloadPacketOrData.ThePacket.header.Offset)
              return this.payloadPacketOrData.ThePacket.SharesMemoryWithSubPackets;
            return false;
          case PayloadType.Bytes:
            return this.header.Bytes == this.payloadPacketOrData.TheByteArraySegment.Bytes && this.header.Offset + this.header.Length == this.payloadPacketOrData.TheByteArraySegment.Offset;
          case PayloadType.None:
            return true;
          default:
            throw new NotImplementedException();
        }
      }
    }

    /// <summary>The packet that is carrying this one</summary>
    public virtual Packet ParentPacket
    {
      get
      {
        return this.parentPacket;
      }
      set
      {
        this.parentPacket = value;
      }
    }

    /// <value>Returns a</value>
    public virtual byte[] Header
    {
      get
      {
        return this.header.ActualBytes();
      }
    }

    /// <summary>
    /// Packet that this packet carries if one is present.
    /// Note that the packet MAY have a null PayloadPacket but
    /// a non-null PayloadData
    /// </summary>
    public virtual Packet PayloadPacket
    {
      get
      {
        return this.payloadPacketOrData.ThePacket;
      }
      set
      {
        if (this == value)
          throw new InvalidOperationException("A packet cannot have itself as its payload.");
        this.payloadPacketOrData.ThePacket = value;
        this.payloadPacketOrData.ThePacket.ParentPacket = this;
      }
    }

    /// <summary>
    /// Payload byte[] if one is present.
    /// Note that the packet MAY have a null PayloadData but a
    /// non-null PayloadPacket
    /// </summary>
    public byte[] PayloadData
    {
      get
      {
        if (this.payloadPacketOrData.TheByteArraySegment == null)
          return (byte[]) null;
        return this.payloadPacketOrData.TheByteArraySegment.ActualBytes();
      }
      set
      {
        this.payloadPacketOrData.TheByteArraySegment = new ByteArraySegment(value, 0, value.Length);
      }
    }

    /// <summary>
    /// byte[] containing this packet and its payload
    /// NOTE: Use 'public virtual ByteArraySegment BytesHighPerformance' for highest performance
    /// </summary>
    public virtual byte[] Bytes
    {
      get
      {
        return this.BytesHighPerformance.ActualBytes();
      }
    }

    /// <value>
    /// The option to return a ByteArraySegment means that this method
    /// is higher performance as the data can start at an offset other than
    /// the first byte.
    /// </value>
    public virtual ByteArraySegment BytesHighPerformance
    {
      get
      {
        this.RecursivelyUpdateCalculatedValues();
        if (this.SharesMemoryWithSubPackets)
          return new ByteArraySegment(this.header.Bytes, this.header.Offset, this.header.BytesLength - this.header.Offset);
        MemoryStream ms = new MemoryStream();
        byte[] header = this.Header;
        ms.Write(header, 0, header.Length);
        this.payloadPacketOrData.AppendToMemoryStream(ms);
        byte[] array = ms.ToArray();
        return new ByteArraySegment(array, 0, array.Length);
      }
    }

    /// <summary>Parse bytes into a packet</summary>
    /// <param name="LinkLayer">
    /// A <see cref="T:PacketDotNet.LinkLayers" /></param>
    /// <param name="PacketData">
    /// A <see cref="T:System.Byte" /></param>
    /// <returns>
    /// A <see cref="T:PacketDotNet.Packet" /></returns>
    public static Packet ParsePacket(LinkLayers LinkLayer, byte[] PacketData)
    {
      ByteArraySegment bas = new ByteArraySegment(PacketData);
      switch (LinkLayer)
      {
        case LinkLayers.Ethernet:
          return (Packet) new EthernetPacket(bas);
        case LinkLayers.Ppp:
          return (Packet) new PPPPacket(bas);
        case LinkLayers.Ieee80211:
          return (Packet) MacFrame.ParsePacket(bas);
        case LinkLayers.LinuxSLL:
          return (Packet) new LinuxSLLPacket(bas);
        case LinkLayers.Ieee80211_Radio:
          return (Packet) new RadioPacket(bas);
        case LinkLayers.PerPacketInformation:
          return (Packet) new PpiPacket(bas);
        default:
          throw new NotImplementedException("LinkLayer of " + (object) LinkLayer + " is not implemented");
      }
    }

    /// <summary>
    /// Used to ensure that values like checksums and lengths are
    /// properly updated
    /// </summary>
    protected void RecursivelyUpdateCalculatedValues()
    {
      this.UpdateCalculatedValues();
      if (this.payloadPacketOrData.Type != PayloadType.Packet)
        return;
      this.payloadPacketOrData.ThePacket.RecursivelyUpdateCalculatedValues();
    }

    /// <summary>
    /// Called to ensure that calculated values are updated before
    /// the packet bytes are retrieved
    /// Classes should override this method to update things like
    /// checksums and lengths that take too much time or are too complex
    /// to update for each packet parameter change
    /// </summary>
    public virtual void UpdateCalculatedValues()
    {
    }

    /// <summary>Output this packet as a readable string</summary>
    public override string ToString()
    {
      return this.ToString(StringOutputType.Normal);
    }

    /// <summary cref="Packet.ToString()">
    /// Output the packet information in the specified format
    /// Normal - outputs the packet info to a single line
    /// Colored - outputs the packet info to a single line with coloring
    /// Verbose - outputs detailed info about the packet
    /// VerboseColored - outputs detailed info about the packet with coloring
    /// </summary>
    /// <param name="outputFormat">
    ///     <see cref="T:PacketDotNet.StringOutputType" />
    /// </param>
    public virtual string ToString(StringOutputType outputFormat)
    {
      if (this.payloadPacketOrData.Type == PayloadType.Packet)
        return this.payloadPacketOrData.ThePacket.ToString(outputFormat);
      return string.Empty;
    }

    /// <summary>
    /// Prints the Packet PayloadData in Hex format
    /// With the 16-byte segment number, raw bytes, and parsed ascii output
    /// Ex:
    /// 0010  00 18 82 6c 7c 7f 00 c0  9f 77 a3 b0 88 64 11 00   ...1|... .w...d..
    /// </summary>
    /// <returns>
    /// A <see cref="T:System.String" /></returns>
    public string PrintHex()
    {
      byte[] bytes = this.BytesHighPerformance.Bytes;
      StringBuilder stringBuilder = new StringBuilder();
      string str1 = "";
      string str2 = "";
      stringBuilder.AppendLine("Data:  ******* Raw Hex Output - length=" + (object) bytes.Length + " bytes");
      stringBuilder.AppendLine("Data: Segment:                   Bytes:                              Ascii:");
      stringBuilder.AppendLine("Data: --------------------------------------------------------------------------");
      for (int index = 1; index <= bytes.Length; ++index)
      {
        str1 = str1 + bytes[index - 1].ToString("x").PadLeft(2, '0') + " ";
        if (bytes[index - 1] < (byte) 33 || bytes[index - 1] > (byte) 126)
          str2 += ".";
        else
          str2 += Encoding.ASCII.GetString(new byte[1]
          {
            bytes[index - 1]
          });
        if (index % 16 != 0 && index % 8 == 0)
        {
          str1 += " ";
          str2 += " ";
        }
        if (index % 16 == 0)
        {
          string str3 = ((index - 16) / 16 * 10).ToString().PadLeft(4, '0');
          stringBuilder.AppendLine("Data: " + str3 + "  " + str1 + "  " + str2);
          str1 = "";
          str2 = "";
        }
        else if (index == bytes.Length)
        {
          string str3 = (((index - 16) / 16 + 1) * 10).ToString().PadLeft(4, '0');
          stringBuilder.AppendLine("Data: " + str3.ToString().PadLeft(4, '0') + "  " + str1.PadRight(49, ' ') + "  " + str2);
        }
      }
      return stringBuilder.ToString();
    }

    /// <summary>
    /// Extract a packet of a specific type or null if a packet of the given type isn't found
    /// NOTE: a 'dynamic' return type is possible here but costs ~7.8% in performance
    /// </summary>
    /// <param name="type">Type.</param>
    public Packet Extract(Type type)
    {
      Packet packet = this;
      while (!type.IsAssignableFrom(packet.GetType()))
      {
        packet = packet.PayloadPacket;
        if (packet == null)
          return (Packet) null;
      }
      return packet;
    }

    /// <value>Color used when generating the text description of a packet</value>
    public virtual string Color
    {
      get
      {
        return AnsiEscapeSequences.Black;
      }
    }
  }
}
