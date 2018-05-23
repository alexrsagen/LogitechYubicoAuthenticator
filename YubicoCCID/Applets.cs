using System.Collections.Generic;

namespace YubicoCCID
{
    public class Applets
    {
        public enum Capability : byte
        {
            OTP = 0x01,
            U2F = 0x02,
            CCID = 0x04,
            OPGP = 0x08,
            PIV = 0x10,
            OATH = 0x20,
            NFC = 0x40
        }

        public struct Applet
        {
            public byte[] AID;
            public Capability Capability;
        }

        public enum Type
        {
            FIDO_U2F,
            YUBICO_U2F,
            YUBICO_OTP,
            YUBICO_PIV,
            YUBICO_OATH,
            YUBICO_MGR,
            OPENPGP
        }

        /// <summary>
        /// A list of all documented official Yubico applets
        /// </summary>
        public static readonly Dictionary<Type, Applet> All = new Dictionary<Type, Applet>() {
            {
                Type.FIDO_U2F,
                new Applet{
                    AID = new byte[] { 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01 },
                    Capability = Capability.U2F
                }
            },
            {
                Type.YUBICO_U2F,
                new Applet{
                    AID = new byte[] { 0xA0, 0x00, 0x00, 0x05, 0x27, 0x10, 0x02 },
                    Capability = Capability.U2F
                }
            },
            {
                Type.YUBICO_OTP,
                new Applet
                {
                    AID = new byte[] { 0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01 },
                    Capability = Capability.OTP
                }
            },
            {
                Type.YUBICO_PIV,
                new Applet{
                    AID = new byte[] { 0xA0, 0x00, 0x00, 0x03, 0x08 },
                    Capability = Capability.PIV
                }
            },
            {
                Type.YUBICO_OATH,
                new Applet{
                    AID = new byte[] { 0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01, 0x01 },
                    Capability = Capability.OATH
                }
            },
            {
                Type.YUBICO_MGR,
                new Applet{
                    AID = new byte[] { 0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17 },
                    Capability = Capability.CCID
                }
            },
            {
                Type.OPENPGP,
                new Applet{
                    AID = new byte[] { 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01 },
                    Capability = Capability.OPGP
                }
            }
        };

        /// <summary>
        /// A list of all applets to probe for in a YubiKey
        /// </summary>
        public static readonly List<Applet> Known = new List<Applet>() {
            All[Type.YUBICO_OTP],
            All[Type.FIDO_U2F],
            All[Type.YUBICO_U2F],
            All[Type.YUBICO_PIV],
            All[Type.OPENPGP],
            All[Type.YUBICO_OATH]
        };
    }
}
