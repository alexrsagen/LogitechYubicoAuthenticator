using System;
using System.Runtime.InteropServices;
using PCSC;

namespace YubicoCCID
{
    public class CCIDDriver : IDisposable
    {
        public enum YKSlotCode : byte
        {
            DEVICE_SERIAL = 0x10,
            DEVICE_CONFIG = 0x11
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ModeData
        {
            public byte Mode;
            public byte ChallengeResponseTimeout;
            public ushort AutoejectTimeout;
        }

        private ISCardContext Context;
        private ISCardReader Reader;
        private bool disposed;
        public uint Serial { get; private set; }
        public Version Version { get; private set; }
        
        /// <summary>
        /// Provides an easy to use CCID wrapper over <see cref="PCSC"/>.
        /// </summary>
        /// <remarks><paramref name="ctx"/> and <paramref name="reader"/> are both disposed of upon class destruction or disposal.</remarks>
        /// <param name="ctx">PCSC carc context</param>
        /// <param name="reader">PCSC card reader</param>
        public CCIDDriver(ISCardContext ctx, ISCardReader reader)
        {
            Context = ctx ?? throw new ArgumentNullException();
            Reader = reader ?? throw new ArgumentNullException();
            ReadVersion();
            ReadSerial();
            byte[] caps = ReadCapabilities();
        }

        /// <summary>
        /// Destructor that ensures the class is disposed of.
        /// </summary>
        ~CCIDDriver() => Dispose(false);

        /// <summary>
        /// Disposes and garbage collects memory used by this class.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Actual disposing code, ensures the class is only disposed of once.
        /// </summary>
        /// <param name="disposing">Whether we are also disposing of related objects</param>
        private void Dispose(bool disposing)
        {
            if (disposed)
                return;
            
            if (disposing && Context != null)
                Context.Dispose();
            if (disposing && Reader != null)
                Reader.Dispose();

            disposed = true;
        }

        /// <summary>
        /// Gets a list of readers connected to the system.
        /// </summary>
        /// <returns>Returns a list of readers.</returns>
        public static string[] ListReaders()
        {
            var contextFactory = ContextFactory.Instance;
            using (var context = contextFactory.Establish(SCardScope.System))
            {
                return context.GetReaders();
            }
        }

        /// <summary>
        /// Creates a new <see cref="CCIDDriver"/> by connecting to the first YubiKey it finds.
        /// </summary>
        /// <returns>Returns a new <see cref="CCIDDriver"/> if a YubiKey is found, otherwise null.</returns>
        public static CCIDDriver OpenDevice()
        {
            foreach (string name in ListReaders())
                if (name.ToLower().StartsWith("yubico yubikey"))
                    return OpenDevice(name, SCardShareMode.Exclusive, SCardProtocol.Any);

            return null;
        }

        /// <summary>
        /// Creates a new <see cref="CCIDDriver"/> by connecting to the device specified by <paramref name="name"/>.
        /// </summary>
        /// <param name="name">Device name</param>
        /// <param name="mode">Connection mode</param>
        /// <param name="protocol">Connection protocol</param>
        /// <returns>Returns a new <see cref="CCIDDriver"/> if the device was found.</returns>
        /// <exception cref="ConnectionException">Thrown if the device is not found or may not be connected to at this time.</exception>
        public static CCIDDriver OpenDevice(string name, SCardShareMode mode = SCardShareMode.Exclusive, SCardProtocol protocol = SCardProtocol.Any)
        {
            ISCardContext ctx = ContextFactory.Instance.Establish(SCardScope.System);
            ISCardReader reader = new SCardReader(ctx);
            if (reader.Connect(name, mode, protocol) != SCardError.Success)
                throw new ConnectionException("Failed to connect to device.");

            return new CCIDDriver(ctx, reader);
        }

        /// <summary>
        /// Transmits an <see cref="APDU"/> to the device and receives an <see cref="APDUResponse"/> back from it.
        /// </summary>
        /// <param name="apdu">APDU to send to the device</param>
        /// <param name="check">Status code to check for</param>
        /// <returns>Returns the parsed <see cref="APDUResponse"/> from the device response.</returns>
        /// <exception cref="UnexpectedResponseException">Thrown if write is unsuccessful or device returns a status code not matching <paramref name="check"/>.</exception>
        public APDUResponse SendAPDU(APDU apdu, APDUResponse.StatusWord? check = APDUResponse.StatusWord.SUCCESS)
        {
            if (apdu == null)
                throw new ArgumentNullException();

            byte[] buffer = new byte[256];
            SCardError writeres = Reader.Transmit(apdu.ToBytes(), ref buffer);
            if (writeres != SCardError.Success)
                throw new UnexpectedResponseException("Device returned a non-success status code.");

            APDUResponse res = new APDUResponse(buffer);

            if (check != null && check != res.SW)
                throw new UnexpectedResponseException("Unexpected response from device.");

            return res;
        }

        /// <summary>
        /// Selects an applet by raw applet ID bytes.
        /// </summary>
        /// <param name="aid">Raw AID</param>
        /// <returns>Returns the parsed <see cref="APDUResponse"/> from the device.</returns>
        /// <exception cref="UnexpectedResponseException">Thrown if unsuccessful.</exception>
        public APDUResponse SelectApplet(byte[] aid)
        {
            return SendAPDU(new APDU
            {
                CLA = 0x00,
                INS = APDU.Instruction.SELECT_FILE,
                P1 = 0x04,
                P2 = 0x00,
                Data = aid
            });
        }

        /// <summary>
        /// Reads the version from the Yubico OTP applet into the class.
        /// </summary>
        /// <exception cref="UnexpectedResponseException">Thrown if unsuccessful.</exception>
        private void ReadVersion()
        {
            // Apparently Yubico OTP applet is capable of delivering Yubikey firmware version
            // who knew
            APDUResponse res = SelectApplet(Applets.All[Applets.Type.YUBICO_OTP].AID);
            Version = new Version(res.Data[0], res.Data[1], res.Data[2]);
        }

        /// <summary>
        /// Reads the serial from the Yubico OTP applet into the class.
        /// </summary>
        /// <exception cref="UnexpectedResponseException">Thrown if unsuccessful.</exception>
        private void ReadSerial()
        {
            APDUResponse res = SendAPDU(new APDU
            {
                CLA = 0x00,
                INS = APDU.Instruction.YK2_REQ,
                P1 = (byte)YKSlotCode.DEVICE_SERIAL,
                P2 = 0x00
            });

            if (res.Data != null && res.Data.Length == 4)
            {
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(res.Data);

                Serial = BitConverter.ToUInt32(res.Data, 0);
            }
        }

        /// <summary>
        /// Sets the YubiKey connection mode.
        /// </summary>
        /// <param name="modeData">YubiKey mode data</param>
        /// <exception cref="UnexpectedResponseException">Thrown if response from device is invalid.</exception>
        /// <exception cref="ModeSwitchException">Thrown if unsuccessful.</exception>
        public void SetMode(ModeData modeData)
        {
            // Convert data struct to byte array
            int size = Marshal.SizeOf(modeData);
            byte[] apduData = new byte[size];
            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(modeData, ptr, true);
            Marshal.Copy(ptr, apduData, 0, size);
            Marshal.FreeHGlobal(ptr);
            
            try
            {
                // First try setting OTP mode
                SetModeOTP(apduData);
            }
            catch (Exception)
            {
                try
                {
                    // Finally try setting MGR mode
                    SetModeMGR(apduData);
                }
                catch (Exception)
                {
                    throw new ModeSwitchException("Failed to switch mode.");
                }
            }
        }

        /// <summary>
        /// Verifies whether a YubiKey programming sequence before and after switching mode is valid
        /// </summary>
        /// <param name="oldPgmSeq">Old programming sequence</param>
        /// <param name="newPgmSeq">New programming sequence</param>
        /// <returns>Returns whether the programming sequence after mode change is valid.</returns>
        private static bool ProgrammingSequenceOK(byte oldPgmSeq, byte newPgmSeq)
        {
            return newPgmSeq == oldPgmSeq || newPgmSeq > oldPgmSeq;
        }

        /// <summary>
        /// Sets the YubiKey connection mode to OTP mode.
        /// </summary>
        /// <param name="data">Raw YubiKey mode data</param>
        /// <exception cref="UnexpectedResponseException">Thrown if the device response is invalid.</exception>
        /// <exception cref="ModeSwitchException">Thrown if the programming sequence is invalid after switching mode.</exception>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="data"/> is null.</exception>
        private void SetModeOTP(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException();

            APDUResponse res;

            // Attempt to select OTP applet
            res = SelectApplet(Applets.All[Applets.Type.YUBICO_OTP].AID);

            if (res.Data == null || res.Data.Length < 4)
                throw new UnexpectedResponseException("Unexpected response from device.");

            byte oldPgmSeq = res.Data[3];

            // Probe for device config
            res = SendAPDU(new APDU
            {
                CLA = 0x00,
                INS = APDU.Instruction.YK2_REQ,
                P1 = (byte)YKSlotCode.DEVICE_CONFIG,
                P2 = 0x00,
                Data = data
            });

            if (res.Data == null || res.Data.Length < 4)
                throw new UnexpectedResponseException("Unexpected response from device.");

            byte newPgmSeq = res.Data[3];
            if (!ProgrammingSequenceOK(oldPgmSeq, newPgmSeq))
                throw new ModeSwitchException("Failed to switch mode.");
        }

        /// <summary>
        /// Sets the YubiKey connection mode to manager mode.
        /// </summary>
        /// <param name="data">Raw YubiKey mode data</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="data"/> is null.</exception>
        private void SetModeMGR(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException();

            // Attempt to select MGR applet
            SelectApplet(Applets.All[Applets.Type.YUBICO_MGR].AID);

            // Probe for device config
            SendAPDU(new APDU
            {
                CLA = 0x00,
                INS = APDU.Instruction.NEO_TEST,
                P1 = (byte)YKSlotCode.DEVICE_CONFIG,
                P2 = 0x00,
                Data = data
            });
        }

        /// <summary>
        /// Attempts to read device capabilities using YubiKey 4 capabilities instruction.
        /// </summary>
        /// <returns>Returns raw device response value.</returns>
        /// <exception cref="UnexpectedResponseException">Thrown if unsuccessful.</exception>
        public byte[] ReadCapabilities()
        {
            try
            {
                // Select manager applet
                SelectApplet(Applets.All[Applets.Type.YUBICO_MGR].AID);

                // Probe for capabilities
                return SendAPDU(new APDU
                {
                    CLA = 0x00,
                    INS = APDU.Instruction.YK4_CAPABILITIES,
                    P1 = 0x00,
                    P2 = 0x00
                }).Data;
            }
            catch (Exception)
            {
                return new byte[0];
            }
        }

        /// <summary>
        /// Attempts to probe device for capabilities.
        /// </summary>
        /// <returns>Returns capabilities flag.</returns>
        public int ProbeCapabilities()
        {
            int capa = 0;
            
            foreach (Applets.Applet applet in Applets.Known)
            {
                try
                {
                    SelectApplet(applet.AID);
                    capa |= (int)applet.Capability;
                }
                catch (UnexpectedResponseException)
                {
                    continue;
                }
            }

            return capa;
        }
    }
}
