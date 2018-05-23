using System;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace YubicoCCID
{
    public class OATHController
    {
        public enum Instruction : byte
        {
            PUT = 0x01,
            DELETE = 0x02,
            SET_CODE = 0x03,
            RESET = 0x04,
            LIST = 0xA1,
            CALCULATE = 0xA2,
            VALIDATE = 0xA3,
            CALCULATE_ALL = 0xA4,
            SEND_REMAINING = 0xA5
        }

        public enum Type : byte
        {
            HOTP = 0x10,
            TOTP = 0x20
        }

        public enum Algo : byte
        {
            HMAC_SHA1 = 0x01,
            HMAC_SHA256 = 0x02,
            HMAC_SHA512 = 0x03
        }

        public enum Mask : byte
        {
            ALGO = 0x0f,
            TYPE = 0xf0
        }

        public enum Property : byte
        {
            ONLY_INCREASING = 0x01,
            REQUIRE_TOUCH = 0x02
        }

        public struct Credential
        {
            public string Name;
            public string Issuer
            {
                get
                {
                    if (Name.Contains(":"))
                    {
                        if (Name.Contains("/"))
                            return Name.Substring(Name.IndexOf("/") + 1, Name.IndexOf(":"));
                        else
                            return Name.Substring(0, Name.IndexOf(":"));
                    }

                    if (Name.Contains("/"))
                        return Name.Substring(Name.IndexOf("/") + 1);
                    else
                        return Name;
                }
            }
            public bool IsSteam => Issuer.Equals("Steam");
            public string Account
            {
                get
                {
                    if (Name.Contains(":"))
                        return Name.Substring(Name.IndexOf(":") + 1);

                    return "";
                }
            }
            public byte Period
            {
                get
                {
                    if (Name.Contains("/"))
                        return byte.Parse(Name.Substring(0, Name.IndexOf("/")));

                    return 30;
                }
            }
            public Algo Algorithm;
            public Type Type;
            public bool Touch;
        }

        public struct Code
        {
            public Credential Credential;
            public string Value;
            public Int32 ValidFrom;
            public Int32 ValidTo;
        }

        const byte MinKeySize = 14;

        private CCIDDriver Driver;
        private Version Version;
        private byte[] Salt;
        private byte[] ID;
        private byte[] Challenge;

        /// <summary>
        /// Controller for the YKOATH protocol, implemented on top of <see cref="CCIDDriver"/>.
        /// </summary>
        public OATHController(CCIDDriver driver)
        {
            Driver = driver ?? throw new ArgumentNullException();
            Select();
        }

        /// <summary>
        /// Sends an APDU to the device connected to the underlying driver.
        /// </summary>
        /// <param name="apdu">APDU to send to the device</param>
        /// <returns>Returns an <see cref="APDUResponse"/> containing response status code and any data.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="apdu"/> is null.</exception>
        /// <exception cref="UnexpectedResponseException">Thrown on a non-success status code.</exception>
        public APDUResponse SendAPDU(APDU apdu)
        {
            // Send APDU and parse response
            APDUResponse res = Driver.SendAPDU(apdu, null);

            // Read remaining data
            while (res.SW1 == (byte)APDUResponse.StatusWord.MORE_DATA_AVAILABLE)
            {
                APDUResponse _res = Driver.SendAPDU(new APDU
                {
                    CLA = 0x00,
                    INS = (APDU.Instruction)Instruction.SEND_REMAINING,
                    P1 = 0x00,
                    P2 = 0x00
                }, null);

                // Extend res.Data with remaining data
                int offset = res.Data.Length;
                Array.Resize(ref res.Data, offset + _res.Data.Length);
                Buffer.BlockCopy(_res.Data, 0, res.Data, offset, _res.Data.Length);

                // Overwrite status words
                res.SW = _res.SW;
            }

            // Validate final status
            if (res.SW != APDUResponse.StatusWord.SUCCESS)
                throw new UnexpectedResponseException("Unexpected response from device.", res.SW);

            // Return full response
            return res;
        }

        /// <summary>
        /// Checks for an unvalidated challenge sent by the device. Use this to check whether the device requires authentication or not.
        /// </summary>
        /// <returns>Returns whether the device requires authentication.</returns>
        public bool HasChallenge()
        {
            return Challenge != null && Challenge.Length > 0;
        }

        /// <summary>
        /// Selects the OATH application for use and initializes the class with device data.
        /// </summary>
        /// <exception cref="UnexpectedResponseException">Thrown on a non-success status code or when the response data is invalid.</exception>
        public void Select()
        {
            APDUResponse res = Driver.SelectApplet(Applets.All[Applets.Type.YUBICO_OATH].AID);

            if (res.Data == null)
                throw new UnexpectedResponseException("Unexpected response from device.");

            var tags = TagLengthValue.FromData(res.Data);
            
            if (!tags.Exists(tag => tag.Tag == TagLengthValue.YKTag.VERSION) ||
                !tags.Exists(tag => tag.Tag == TagLengthValue.YKTag.NAME))
                throw new UnexpectedResponseException("Unexpected response from device.");

            byte[] version = tags.Find(tag => tag.Tag == TagLengthValue.YKTag.VERSION).Value;

            Version = new Version(version[0], version[1], version[2]);
            Salt = tags.Find(tag => tag.Tag == TagLengthValue.YKTag.NAME).Value;
            ID = GetDeviceID(Salt);

            if (tags.Exists(tag => tag.Tag == TagLengthValue.YKTag.CHALLENGE))
                Challenge = tags.Find(tag => tag.Tag == TagLengthValue.YKTag.CHALLENGE).Value;

            // Yubico ignores this in their ykman Python SDK...
            //if (tags.Exists(tag => tag.Tag == TagLengthValue.YKTag.ALGORITHM)
            //    ChallengeAlgo = tags.Find(tag => tag.Tag == TagLengthValue.YKTag.ALGORITHM).Value;
        }

        /// <summary>
        /// Adds a new Base-32 encoded secret as an OATH entry on the device.
        /// </summary>
        /// <param name="key">Base-32 encoded secret</param>
        /// <param name="name">Name of the entry</param>
        /// <param name="type">Entry type (HOTP/TOTP)</param>
        /// <param name="digits">Output code digits</param>
        /// <param name="algo">Entry algorithm (SHA1/SHA256/SHA512)</param>
        /// <param name="counter">HOTP counter</param>
        /// <param name="requireTouch">Whether the new entry should require touch when calling <see cref="Calculate(Credential, DateTime?)"/></param>
        /// <exception cref="KeyExistsException">Thrown when an entry by that name already exists.</exception>
        /// <exception cref="UnexpectedResponseException">Thrown on a non-success status code.</exception>
        public void Put(string key, string name, Type type = Type.TOTP, byte digits = 6, Algo algo = Algo.HMAC_SHA1, uint counter = 0, bool requireTouch = false)
        {
            Put(Base32.ToBytes(key.ToUpper().Replace(" ", "")), name, type, digits, algo, counter, requireTouch);
        }

        /// <summary>
        /// Adds a new raw secret as an OATH entry on the device.
        /// </summary>
        /// <param name="key">Base-32 encoded secret</param>
        /// <param name="name">Name of the entry</param>
        /// <param name="type">Entry type (HOTP/TOTP)</param>
        /// <param name="digits">Output code digits</param>
        /// <param name="algo">Entry algorithm (SHA1/SHA256/SHA512)</param>
        /// <param name="counter">HOTP counter</param>
        /// <param name="requireTouch">Whether the new entry should require touch when calling <see cref="Calculate(Credential, DateTime?)"/></param>
        /// <exception cref="KeyExistsException">Thrown when an entry by that name already exists.</exception>
        /// <exception cref="UnexpectedResponseException">Thrown on a non-success status code.</exception>
        public void Put(byte[] secret, string name, Type type = Type.TOTP, byte digits = 6, Algo algo = Algo.HMAC_SHA1, uint counter = 0, bool requireTouch = false)
        {
            if (List().Exists(item => item.Name.Equals(name)))
                throw new KeyExistsException("A key with that name already exists.");

            TagLengthValue tlvName = new TagLengthValue(TagLengthValue.YKTag.NAME, Encoding.UTF8.GetBytes(name));
            byte[] tlvSecretData = null;
            TagLengthValue tlvSecret = null;
            byte[] tvProperties = null;
            TagLengthValue tlvIMF = null;
            byte[] tlvIMFData = null;
            byte[] apduData = null;
            int apduDataLen = 0;

            // hmac_shorten_key
            switch (algo)
            {
                case Algo.HMAC_SHA1:
                    using (SHA1 sha = new SHA1CryptoServiceProvider())
                    {
                        if (secret.Length > 64)
                        {
                            int shaBytes = sha.HashSize / 8;
                            tlvSecretData = new byte[2 + Math.Max(MinKeySize, shaBytes)];
                            Buffer.BlockCopy(sha.ComputeHash(secret), 0, tlvSecretData, 2, shaBytes);
                        }
                        else
                        {
                            tlvSecretData = new byte[2 + Math.Max(MinKeySize, secret.Length)];
                            Buffer.BlockCopy(secret, 0, tlvSecretData, 2, secret.Length);
                        }
                    }
                    break;
                case Algo.HMAC_SHA256:
                    using (SHA256 sha = new SHA256CryptoServiceProvider())
                    {
                        if (secret.Length > 64)
                        {
                            int shaBytes = sha.HashSize / 8;
                            tlvSecretData = new byte[2 + Math.Max(MinKeySize, shaBytes)];
                            Buffer.BlockCopy(sha.ComputeHash(secret), 0, tlvSecretData, 2, shaBytes);
                        }
                        else
                        {
                            tlvSecretData = new byte[2 + Math.Max(MinKeySize, secret.Length)];
                            Buffer.BlockCopy(secret, 0, tlvSecretData, 2, secret.Length);
                        }
                    }
                    break;
                case Algo.HMAC_SHA512:
                    using (SHA512 sha = new SHA512CryptoServiceProvider())
                    {
                        if (secret.Length > 128)
                        {
                            int shaBytes = sha.HashSize / 8;
                            tlvSecretData = new byte[2 + Math.Max(MinKeySize, shaBytes)];
                            Buffer.BlockCopy(sha.ComputeHash(secret), 0, tlvSecretData, 2, shaBytes);
                        }
                        else
                        {
                            tlvSecretData = new byte[2 + Math.Max(MinKeySize, secret.Length)];
                            Buffer.BlockCopy(secret, 0, tlvSecretData, 2, secret.Length);
                        }
                    }
                    break;
            }

            tlvSecretData[0] = (byte)((byte)type | (byte)algo);
            tlvSecretData[1] = digits;
            tlvSecret = new TagLengthValue(TagLengthValue.YKTag.KEY, tlvSecretData);

            // Calculate correct length of apduData
            apduDataLen += tlvName.Data.Length + tlvSecret.Data.Length;
            if (requireTouch)
            {
                tvProperties = new byte[2] { (byte)TagLengthValue.YKTag.PROPERTY, (byte)Property.REQUIRE_TOUCH };
                apduDataLen += tvProperties.Length;
            }
            if (counter > 0)
            {
                tlvIMFData = BitConverter.GetBytes(counter);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(tlvIMFData);
                tlvIMF = new TagLengthValue(TagLengthValue.YKTag.IMF, tlvIMFData);
                apduDataLen += tlvIMF.Data.Length;
            }

            // Initialize apduData with correct length
            apduData = new byte[apduDataLen];

            // Fill apduData with previously constructed TLV data
            int offset = 0;
            Buffer.BlockCopy(tlvName.Data, 0, apduData, offset, tlvName.Data.Length);
            offset += tlvName.Data.Length;
            Buffer.BlockCopy(tlvSecret.Data, 0, apduData, offset, tlvSecret.Data.Length);
            offset += tlvSecret.Data.Length;
            if (tvProperties != null)
            {
                Buffer.BlockCopy(tvProperties, 0, apduData, offset, tvProperties.Length);
                offset += tvProperties.Length;
            }
            if (tlvIMF != null)
            {
                Buffer.BlockCopy(tlvIMF.Data, 0, apduData, offset, tlvIMF.Data.Length);
                offset += tlvIMF.Data.Length;
            }

            // Send APDU to device
            SendAPDU(new APDU
            {
                CLA = 0x00,
                INS = (APDU.Instruction)Instruction.PUT,
                P1 = 0x00,
                P2 = 0x00,
                Data = apduData
            });
        }

        /// <summary>
        /// Deletes an existing OATH entry from the device.
        /// </summary>
        /// <param name="name">Name of the entry to delete</param>
        /// <exception cref="UnexpectedResponseException">Thrown on a non-success status code.</exception>
        public void Delete(string name)
        {
            TagLengthValue tlvName = new TagLengthValue(TagLengthValue.YKTag.NAME, Encoding.UTF8.GetBytes(name));

            SendAPDU(new APDU
            {
                CLA = 0x00,
                INS = (APDU.Instruction)Instruction.DELETE,
                P1 = 0x00,
                P2 = 0x00,
                Data = tlvName.Data
            });
        }

        /// <summary>
        /// Configures device authentication.
        /// </summary>
        /// <param name="password">New device password</param>
        /// <exception cref="UnexpectedResponseException">Thrown on a non-success status code.</exception>
        public void SetCode(string password)
        {
            byte[] key = DeriveKey(password);
            HMACSHA1 hmac = new HMACSHA1(key);
            byte[] tlvKeyData = new byte[1 + key.Length];
            Buffer.BlockCopy(key, 0, tlvKeyData, 1, key.Length);
            tlvKeyData[0] = (byte)Type.TOTP | (byte)Algo.HMAC_SHA1;
            byte[] tlvChallengeData = new byte[8];
            Random random = new Random();
            random.NextBytes(tlvChallengeData);
            TagLengthValue tlvKey = new TagLengthValue(TagLengthValue.YKTag.KEY, tlvKeyData);
            TagLengthValue tlvChallenge = new TagLengthValue(TagLengthValue.YKTag.CHALLENGE, tlvChallengeData);
            TagLengthValue tlvResponse = new TagLengthValue(TagLengthValue.YKTag.RESPONSE, hmac.ComputeHash(tlvChallengeData));
            byte[] apduData = null;
            int apduDataLen = 0;

            // Calculate correct length of apduData
            apduDataLen += tlvKey.Data.Length;
            apduDataLen += tlvChallenge.Data.Length;
            apduDataLen += tlvResponse.Data.Length;

            // Initialize apduData with correct length
            apduData = new byte[apduDataLen];

            // Fill apduData with previously constructed TLV data
            int offset = 0;
            Buffer.BlockCopy(tlvKey.Data, 0, apduData, offset, tlvKey.Data.Length);
            offset += tlvKey.Data.Length;
            Buffer.BlockCopy(tlvChallenge.Data, 0, apduData, offset, tlvChallenge.Data.Length);
            offset += tlvChallenge.Data.Length;
            Buffer.BlockCopy(tlvResponse.Data, 0, apduData, offset, tlvResponse.Data.Length);
            offset += tlvResponse.Data.Length;

            // Send APDU to device
            SendAPDU(new APDU
            {
                CLA = 0x00,
                INS = (APDU.Instruction)Instruction.SET_CODE,
                P1 = 0x00,
                P2 = 0x00,
                Data = apduData
            });
        }

        /// <summary>
        /// Removes device authentication.
        /// </summary>
        /// <exception cref="UnexpectedResponseException">Thrown on a non-success status code.</exception>
        public void ClearCode() {
            SendAPDU(new APDU
            {
                CLA = 0x00,
                INS = (APDU.Instruction)Instruction.SET_CODE,
                P1 = 0x00,
                P2 = 0x00,
                Data = new byte[0]
            });
        }

        /// <summary>
        /// Resets the application to just-installed state.
        /// </summary>
        /// <exception cref="UnexpectedResponseException">Thrown on a non-success status code.</exception>
        public void Reset()
        {
            SendAPDU(new APDU
            {
                CLA = 0x00,
                INS = (APDU.Instruction)Instruction.RESET,
                P1 = 0xDE,
                P2 = 0xAD
            });
        }

        /// <summary>
        /// Lists configured credentials.
        /// </summary>
        /// <returns>Returns a list of configured credentials.</returns>
        /// <exception cref="UnexpectedResponseException">Thrown on a non-success status code.</exception>
        public List<Credential> List()
        {
            APDUResponse res = SendAPDU(new APDU
            {
                CLA = 0x00,
                INS = (APDU.Instruction)Instruction.LIST,
                P1 = 0x00,
                P2 = 0x00
            });

            List<Credential> list = new List<Credential>();
            var tags = TagLengthValue.FromData(res.Data);
            foreach (var tag in tags)
            {
                if (tag.Tag != TagLengthValue.YKTag.NAME_LIST)
                    continue;

                Algo algo = (Algo)((byte)Mask.ALGO & tag.Value[0]);
                if (!Enum.IsDefined(typeof(Algo), algo))
                    throw new UnexpectedResponseException("Device returned item with unexpected algorithm.");

                Type type = (Type)((byte)Mask.TYPE & tag.Value[0]);
                if (!Enum.IsDefined(typeof(Type), type))
                    throw new UnexpectedResponseException("Device returned item with unexpected type.");

                list.Add(new Credential {
                    Name = Encoding.UTF8.GetString(tag.Value, 1, tag.Value.Length - 1),
                    Algorithm = algo,
                    Type = type
                });
            }

            return list;
        }

        /// <summary>
        /// Calculates a HOTP or TOTP code for one <see cref="Credential"/>.
        /// </summary>
        /// <param name="cred">The <see cref="Credential"/> to generate a code for</param>
        /// <param name="time">The <see cref="DateTime"/> to generate a TOTP code at</param>
        /// <returns>Returns a new <see cref="Code"/></returns>
        /// <exception cref="ArgumentException">Thrown when an invalid credential type is passed.</exception>
        /// <exception cref="UnexpectedResponseException">Thrown on a non-success status code or when response data is invalid.</exception>
        public Code Calculate(Credential cred, DateTime? time = null)
        {
            // The 4.2.0-4.2.6 firmwares have a known issue with credentials that
            // require touch: If this action is performed within 2 seconds of a
            // command resulting in a long response (over 54 bytes),
            // the command will hang. A workaround is to send an invalid command
            // (resulting in a short reply) prior to the "calculate" command.
            if (cred.Touch && Version.CompareTo(new Version(4, 2, 0)) >= 0 && Version.CompareTo(new Version(4, 2, 6)) <= 0)
            {
                Driver.SendAPDU(new APDU
                {
                    CLA = 0x00,
                    INS = 0x00,
                    P1 = 0x00,
                    P2 = 0x00,
                    Data = new byte[0]
                }, null);
            }

            if (time == null)
                time = DateTime.UtcNow;

            Int32 timestamp = (Int32)(time.Value.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            Int32 validFrom = 0;
            Int32 validTo = 0;
            byte[] challenge = new byte[8];
            
            switch (cred.Type)
            {
                case Type.TOTP:
                    validFrom = timestamp - (timestamp % cred.Period);
                    validTo = validFrom + cred.Period;
                    byte[] totpChallenge = BitConverter.GetBytes(timestamp / cred.Period);
                    if (BitConverter.IsLittleEndian)
                        Array.Reverse(totpChallenge);
                    Buffer.BlockCopy(totpChallenge, 0, challenge, 4, 4);
                    break;

                case Type.HOTP:
                    validFrom = timestamp;
                    break;

                default:
                    throw new ArgumentException("Invalid credential type.", "cred");
            }

            TagLengthValue tlvName = new TagLengthValue(TagLengthValue.YKTag.NAME, Encoding.UTF8.GetBytes(cred.Name));
            TagLengthValue tlvChallenge = new TagLengthValue(TagLengthValue.YKTag.CHALLENGE, challenge);
            byte[] apduData = null;
            int apduDataLen = 0;

            // Calculate correct length of apduData
            apduDataLen += tlvName.Data.Length;
            apduDataLen += tlvChallenge.Data.Length;

            // Initialize apduData with correct length
            apduData = new byte[apduDataLen];

            // Fill apduData with previously constructed TLV data
            int offset = 0;
            Buffer.BlockCopy(tlvName.Data, 0, apduData, offset, tlvName.Data.Length);
            offset += tlvName.Data.Length;
            Buffer.BlockCopy(tlvChallenge.Data, 0, apduData, offset, tlvChallenge.Data.Length);
            offset += tlvChallenge.Data.Length;

            // Send APDU to device
            APDUResponse res = SendAPDU(new APDU
            {
                CLA = 0x00,
                INS = (APDU.Instruction)Instruction.CALCULATE,
                P1 = 0x00,
                P2 = 0x01,
                Data = apduData
            });

            var tags = TagLengthValue.FromData(res.Data);

            if (!tags.Exists(tag => tag.Tag == TagLengthValue.YKTag.TRUNCATED_RESPONSE))
                throw new UnexpectedResponseException("Unexpected response from device.");

            byte[] resValue = tags.Find(tag => tag.Tag == TagLengthValue.YKTag.TRUNCATED_RESPONSE).Value;
            return new Code
            {
                Credential = cred,
                ValidFrom = validFrom,
                ValidTo = validTo,
                Value = FormatCode(resValue)
            };
        }

        /// <summary>
        /// Validates authentication (mutually).
        /// </summary>
        /// <param name="password">Password to unlock the device with</param>
        public void Validate(string password)
        {
            HMACSHA1 hmac = new HMACSHA1(DeriveKey(password));
            TagLengthValue tlvResponse = new TagLengthValue(TagLengthValue.YKTag.RESPONSE, hmac.ComputeHash(Challenge));
            byte[] tlvChallengeData = new byte[8];
            Random random = new Random();
            random.NextBytes(tlvChallengeData);
            byte[] expectedResponse = hmac.ComputeHash(tlvChallengeData);
            TagLengthValue tlvChallenge = new TagLengthValue(TagLengthValue.YKTag.CHALLENGE, tlvChallengeData);
            byte[] apduData = null;
            int apduDataLen = 0;

            // Calculate correct length of apduData
            apduDataLen += tlvResponse.Data.Length;
            apduDataLen += tlvChallenge.Data.Length;

            // Initialize apduData with correct length
            apduData = new byte[apduDataLen];

            // Fill apduData with previously constructed TLV data
            int offset = 0;
            Buffer.BlockCopy(tlvResponse.Data, 0, apduData, offset, tlvResponse.Data.Length);
            offset += tlvResponse.Data.Length;
            Buffer.BlockCopy(tlvChallenge.Data, 0, apduData, offset, tlvChallenge.Data.Length);
            offset += tlvChallenge.Data.Length;

            // Send APDU to device
            APDUResponse res = SendAPDU(new APDU{
                CLA = 0x00,
                INS = (APDU.Instruction)Instruction.VALIDATE,
                P1 = 0x00,
                P2 = 0x00,
                Data = apduData
            });
            
            if (res.Data == null)
                throw new UnexpectedResponseException("No response from card.");

            var tags = TagLengthValue.FromData(res.Data);

            if (!tags.Exists(tag => tag.Tag == TagLengthValue.YKTag.RESPONSE))
                throw new UnexpectedResponseException("Unexpected response from device.");

            if (!tags.Find(tag => tag.Tag == TagLengthValue.YKTag.RESPONSE).ValueEquals(expectedResponse))
                throw new UnexpectedResponseException("Incorrect response from device.", APDUResponse.StatusWord.INCORRECT_RESPONSE);

            Challenge = null;
        }

        /// <summary>
        /// Performs <see cref="Calculate(Credential, DateTime?)"/> for all available TOTP credentials that do not require touch.
        /// </summary>
        /// <param name="time">The <see cref="DateTime"/> to generate a TOTP code at</param>
        /// <returns>Returns codes for all TOTP credentials that do not require touch.</returns>
        public List<Code> CalculateAll(DateTime? time = null)
        {
            if (time == null)
                time = DateTime.UtcNow;

            Int32 timestamp = (Int32)(time.Value.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            byte[] challenge = new byte[8];
            byte[] totpChallenge = BitConverter.GetBytes(timestamp / 30);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(totpChallenge);
            Buffer.BlockCopy(totpChallenge, 0, challenge, 4, 4);
            TagLengthValue tlvChallenge = new TagLengthValue(TagLengthValue.YKTag.CHALLENGE, challenge);

            APDUResponse res = SendAPDU(new APDU{
                CLA = 0x00,
                INS = (APDU.Instruction)Instruction.CALCULATE_ALL,
                P1 = 0x00,
                P2 = 0x01,
                Data = tlvChallenge.Data
            });

            List<Code> codes = new List<Code>();
            var tags = TagLengthValue.FromData(res.Data);
            if (tags.Count % 2 != 0)
                throw new UnexpectedResponseException("Unexpected tag count from device.");

            for (int i = 0; i < tags.Count; i += 2)
            {
                if (tags[i].Tag != TagLengthValue.YKTag.NAME)
                    throw new UnexpectedResponseException("Unexpected tag order from device.");

                Credential cred = new Credential
                {
                    Name = Encoding.UTF8.GetString(tags[i].Value),
                };
                Int32 validFrom = timestamp - (timestamp % cred.Period);
                Int32 validTo = validFrom + cred.Period;
                Code code;

                switch (tags[i + 1].Tag)
                {
                    case TagLengthValue.YKTag.TOUCH:
                        cred.Touch = true;
                        code = new Code
                        {
                            Credential = cred
                        };
                        break;

                    case TagLengthValue.YKTag.HOTP:
                        code = new Code{
                            Credential = cred
                        };
                        break;

                    case TagLengthValue.YKTag.TRUNCATED_RESPONSE:
                        if (cred.Period != 30 || cred.IsSteam)
                        {
                            code = Calculate(cred);
                        }
                        else
                        {
                            code = new Code
                            {
                                Credential = cred,
                                ValidFrom = validFrom,
                                ValidTo = validTo,
                                Value = FormatCode(tags[i + 1].Value)
                            };
                        }
                        break;

                    case TagLengthValue.YKTag.RESPONSE:
                    default:
                        throw new UnexpectedResponseException("Unexpected tag from device.");
                }

                codes.Add(code);
            }

            return codes;
        }

        /// <summary>
        /// Parses code from a truncated response.
        /// </summary>
        /// <param name="response">Truncated response from device</param>
        /// <returns>Returns a human-readable TOTP/HOTP code with correct length.</returns>
        private string FormatCode(byte[] response)
        {
            byte digits = response[0];
            byte[] codeBytes = new byte[4];
            Buffer.BlockCopy(response, 1, codeBytes, 0, 4);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(codeBytes);
            uint code = BitConverter.ToUInt32(codeBytes, 0) & 0x7FFFFFFF;

            return FormatCode(code, digits);
        }

        /// <summary>
        /// Formats a code with the correct length or alphabet.
        /// </summary>
        /// <param name="code">The code to format</param>
        /// <param name="digits">Code length</param>
        /// <param name="steam">Indicates whether the code is a Steam Guard code</param>
        /// <returns>Returns the formatted code.</returns>
        private string FormatCode(uint code, byte digits = 6, bool steam = false)
        {
            const string STEAM_CHARS = "23456789BCDFGHJKMNPQRTVWXY";
            string retval = "";

            if (steam)
            {
                for (byte i = 0; i < 5; i++)
                {
                    retval += STEAM_CHARS[(int)(code % STEAM_CHARS.Length)];
                    code /= (uint)STEAM_CHARS.Length;
                }
            }
            else
            {
                retval = (code % Math.Pow(10, digits)).ToString();
                while (retval.Length < digits)
                    retval = "0" + retval;
            }

            return retval;
        }

        /// <summary>
        /// Derives a key from a user-given password using the device ID as salt.
        /// </summary>
        /// <param name="password">Password to derive a key from</param>
        /// <returns>Returns the hashed and salted password.</returns>
        private byte[] DeriveKey(string password)
        {
            using (Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(password), Salt, 1000))
            {
                return kdf.GetBytes(16);
            }
        }

        /// <summary>
        /// Gets a device identifier from a device salt.
        /// </summary>
        /// <param name="deviceSalt">Device salt</param>
        /// <returns>Returns the device identifier for the given salt.</returns>
        private static byte[] GetDeviceID(byte[] deviceSalt)
        {
            byte[] deviceId = new byte[16];
            using (SHA256 sha = new SHA256CryptoServiceProvider())
            {
                Buffer.BlockCopy(sha.ComputeHash(deviceSalt), (sha.HashSize / 8) - 16, deviceId, 0, 16);
            }
            return Encoding.UTF8.GetBytes(Convert.ToBase64String(deviceId).Replace("=", ""));
        }
    }
}
