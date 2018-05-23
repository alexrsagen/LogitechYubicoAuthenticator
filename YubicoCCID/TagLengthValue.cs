using System;
using System.Collections.Generic;

namespace YubicoCCID
{
    /// <summary>
    /// Class for parsing and holding TLV data.
    /// </summary>
    public class TagLengthValue
    {
        public enum YKTag : byte
        {
            NAME = 0x71,
            NAME_LIST = 0x72,
            KEY = 0x73,
            CHALLENGE = 0x74,
            RESPONSE = 0x75,
            TRUNCATED_RESPONSE = 0x76,
            HOTP = 0x77,
            PROPERTY = 0x78,
            VERSION = 0x79,
            IMF = 0x7A,
            ALGORITHM = 0x7B,
            TOUCH = 0x7C
        }
        
        public int Length { get; private set; }
        public YKTag Tag { get; private set; }
        public byte[] Value { get; private set; }
        public byte[] Data { get; private set; }

        /// <summary>
        /// Parses TLV data from raw APDU data.
        /// </summary>
        /// <param name="data">Raw APDU data</param>
        public TagLengthValue(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException();
            if (data.Length < 2)
                throw new ArgumentException("data length must be at least 2");
            if (!Enum.IsDefined(typeof(YKTag), data[0]))
                throw new ArgumentException("data contains an invalid tag");
            
            Tag = (YKTag)data[0];
            Length = data[1];
            int offset = 2;
            if (Length > 0x80)
            {
                int n_bytes = Length - 0x80;

                // b2len
                Length = 0;
                for (int i = 0; i < n_bytes; i++)
                {
                    Length *= 256;
                    Length += data[offset + i];
                }

                offset += n_bytes;
            }

            Value = new byte[Length];
            Buffer.BlockCopy(data, offset, Value, 0, Length);

            ReconstructData();
        }

        /// <summary>
        /// Creates TLV data from an <see cref="YKTag"/>.
        /// </summary>
        /// <param name="tag">TLV tag</param>
        public TagLengthValue(YKTag tag) : this((byte)tag) { }

        /// <summary>
        /// Creates TLV data from a tag byte.
        /// </summary>
        /// <param name="tag"></param>
        public TagLengthValue(byte tag)
        {
            if (!Enum.IsDefined(typeof(YKTag), tag))
                throw new ArgumentException("tag is invalid");

            Tag = (YKTag)tag;
            Value = new byte[0];

            ReconstructData();
        }

        /// <summary>
        /// Creates TLV data from an <see cref="YKTag"/> and value data.
        /// </summary>
        /// <param name="tag">TLV tag</param>
        /// <param name="value">TLV value</param>
        public TagLengthValue(YKTag tag, byte[] value) : this((byte)tag, value) { }

        /// <summary>
        /// Creates TLV data from a tag byte and value data.
        /// </summary>
        /// <param name="tag">TLV tag</param>
        /// <param name="value">TLV value</param>
        public TagLengthValue(byte tag, byte[] value)
        {
            if (!Enum.IsDefined(typeof(YKTag), tag))
                throw new ArgumentException("tag is invalid");

            Tag = (YKTag)tag;
            Value = value ?? throw new ArgumentNullException();

            ReconstructData();
        }

        /// <summary>
        /// Compares a TLV value byte for byte.
        /// </summary>
        /// <param name="compareTo">TLV value to compare against</param>
        /// <returns>Returns whether the two <see cref="TagLengthValue"/> values are equal.</returns>
        public bool ValueEquals(byte[] compareTo)
        {
            if (Value == compareTo) return true;
            if (Value == null || compareTo == null) return false;
            if (Value.Length != compareTo.Length) return false;
            for (int i = 0; i < Value.Length; i++)
                if (Value[i] != compareTo[i]) return false;
            return true;
        }

        /// <summary>
        /// Creates a human-readable representation of class data.
        /// </summary>
        /// <returns>Returns a string containing a human-readable representation of class data.</returns>
        public override string ToString()
        {
            return base.ToString() +
                string.Format("(tag={0:X2}, value={1})", Tag, BitConverter.ToString(Value).Replace("-", ""));
        }

        /// <summary>
        /// Parses raw APDU data into a list of several <see cref="TagLengthValue"/> instances.
        /// </summary>
        /// <param name="data">Raw APDU data</param>
        /// <returns>Returns a list of <see cref="TagLengthValue"/> instances.</returns>
        public static List<TagLengthValue> FromData(byte[] data)
        {
            List<TagLengthValue> tags = new List<TagLengthValue>();

            int offset = 0;
            while (offset < data.Length)
            {
                byte[] offsetData = new byte[data.Length - offset];
                Buffer.BlockCopy(data, offset, offsetData, 0, data.Length - offset);
                TagLengthValue tlv = new TagLengthValue(offsetData);
                tags.Add(tlv);
                offset += tlv.Data.Length;
            }

            return tags;
        }

        /// <summary>
        /// Reconstructs TLV data from tag and value.
        /// </summary>
        public void ReconstructData()
        {
            if (Value.Length < 0x80)
            {
                Data = new byte[2 + Value.Length];
                Data[0] = (byte)Tag;
                Data[1] = (byte)Value.Length;
                Buffer.BlockCopy(Value, 0, Data, 2, Value.Length);
            }
            else if (Value.Length < 0xFF)
            {
                Data = new byte[3 + Value.Length];
                Data[0] = (byte)Tag;
                Data[1] = 0x81;
                Data[2] = (byte)Value.Length;
                Buffer.BlockCopy(Value, 0, Data, 3, Value.Length);
            }
            else
            {
                Data = new byte[4 + Value.Length];
                Data[0] = (byte)Tag;
                Data[1] = 0x82;
                Data[2] = (byte)(Value.Length >> 8);
                Data[3] = (byte)(Value.Length & 0xFF);
                Buffer.BlockCopy(Value, 0, Data, 4, Value.Length);
            }
        }
    }
}
