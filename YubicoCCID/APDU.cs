using System;
using System.Text;

namespace YubicoCCID
{
    /// <summary>
    /// Class for creating and holding APDU request data
    /// </summary>
    public class APDU
    {
        public enum Instruction : byte
        {
            SELECT_FILE = 0xA4,
            YK4_CAPABILITIES = 0x1D,
            YK2_REQ = 0x01,
            NEO_TEST = 0x16
        }

        public byte CLA;
        public Instruction INS;
        public byte P1;
        public byte P2;
        public byte Le = 254;
        public byte[] Data;

        /// <summary>
        /// Data constructor
        /// </summary>
        public APDU() : base() { }

        /// <summary>
        /// Parses raw request bytes
        /// </summary>
        /// <param name="raw">Raw request data</param>
        public APDU(byte[] raw)
        {
            if (raw == null)
                throw new ArgumentNullException("raw");

            if (raw.Length < 4)
                throw new ArgumentException("Data too short.", "raw");

            CLA = raw[0];
            INS = (Instruction)raw[1];
            P1 = raw[2];
            P2 = raw[3];

            if (raw.Length > 4)
            {
                if (raw.Length == 4 + raw[4] + 1)
                    Le = raw[raw[4] + 1];
                else if (raw.Length > 4 + raw[4] + 1)
                    throw new ArgumentException("Data too long.", "raw");

                Data = new byte[raw[4]];
                Buffer.BlockCopy(raw, 5, Data, 0, raw[4]);
            }
        }

        /// <summary>
        /// Turns the data held by the class into a hex-encoded APDU request
        /// </summary>
        /// <returns>Returns a string containing hex-encoded request bytes</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(CLA.ToString("X2"));
            sb.Append(((byte)INS).ToString("X2"));
            sb.Append(P1.ToString("X2"));
            sb.Append(P2.ToString("X2"));

            if (Data == null || Data.Length == 0)
            {
                sb.Append(Le.ToString("X2"));
                return sb.ToString();
            }

            sb.Append(((byte)Data.Length).ToString("X2"));

            foreach (byte b in Data)
                sb.Append(b.ToString("X2"));

            sb.Append(Le.ToString("X2"));

            return sb.ToString();
        }

        /// <summary>
        /// Turns the data held by the class into an APDU byte array
        /// </summary>
        /// <returns>Returns a byte array containing raw APDU data</returns>
        public byte[] ToBytes()
        {
            int rawLength = 5;

            if (Data != null)
                rawLength += 1 + Data.Length;

            byte[] raw = new byte[rawLength];
            raw[0] = CLA;
            raw[1] = (byte)INS;
            raw[2] = P1;
            raw[3] = P2;

            if (Data == null || Data.Length == 0)
            {
                raw[4] = Le;
                return raw;
            }
            
            raw[4] = (byte)Data.Length;
            Buffer.BlockCopy(Data, 0, raw, 5, Data.Length);
            raw[5 + Data.Length] = Le;

            return raw;
        }
    }

    /// <summary>
    /// Class for parsing and holding APDU response data
    /// </summary>
    public class APDUResponse
    {
        /// <summary>
        /// Contains all documented YubiKey status words in use by the YKOATH protocol
        /// </summary>
        public enum StatusWord : ushort
        {
            SUCCESS = 0x9000,
            INCORRECT_RESPONSE = 0x6984,
            NO_SUCH_OBJECT = 0x6984,
            AUTH_NOT_ENABLED = 0x6984,
            NO_SPACE = 0x6A84,
            AUTH_REQUIRED = 0x6982,
            WRONG_SYNTAX = 0x6A80,
            GENERIC_ERROR = 0x6581,
            MORE_DATA_AVAILABLE = 0x61,
            INVALID_INSTRUCTION = 0x6D00,
            COMMAND_ABORTED = 0x6F00
        }

        public byte SW1;
        public byte SW2;
        public StatusWord SW
        {
            get
            {
                return (StatusWord)((SW1 << 8) + SW2);
            }
            set
            {
                SW1 = (byte)((ushort)value >> 8);
                SW2 = (byte)((ushort)value & 0xFF);
            }
        }
        public byte[] Data;

        /// <summary>
        /// Parses raw response bytes
        /// </summary>
        /// <param name="raw">Raw response data</param>
        public APDUResponse(byte[] raw)
        {
            if (raw == null)
                throw new ArgumentNullException("raw");

            if (raw.Length < 2)
                throw new ArgumentException("Data too short.", "raw");

            if (raw.Length > 2)
            {
                Data = new byte[raw.Length - 2];
                Buffer.BlockCopy(raw, 0, Data, 0, raw.Length - 2);
            }

            SW1 = raw[raw.Length - 2];
            SW2 = raw[raw.Length - 1];
        }

        /// <summary>
        /// Turns the data held by the class into a hex-encoded APDU response
        /// </summary>
        /// <returns>Returns a string containing hex-encoded response bytes</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(SW1.ToString("X2"));
            sb.Append(SW2.ToString("X2"));

            if (Data == null || Data.Length == 0)
                return sb.ToString();

            foreach (byte b in Data)
                sb.Append(b.ToString("X2"));

            return sb.ToString();
        }

        /// <summary>
        /// Turns the data held by the class into an APDU byte array
        /// </summary>
        /// <returns>Returns a byte array containing raw APDU data</returns>
        public byte[] ToBytes()
        {
            int rawLength = 2;

            if (Data != null)
                rawLength += Data.Length;

            byte[] raw = new byte[rawLength];
            raw[0] = SW1;
            raw[1] = SW2;

            if (Data != null)
                Buffer.BlockCopy(Data, 0, raw, 2, Data.Length);

            return raw;
        }
    }
}
