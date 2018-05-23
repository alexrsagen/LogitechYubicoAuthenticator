using System;

namespace YubicoCCID
{
    public class APDUException : Exception
    {
        public APDUResponse.StatusWord SW { get; protected set; }

        public APDUException() { }
        public APDUException(string message) : base(message) { }
        public APDUException(string message, Exception inner) : base(message, inner) { }
        public APDUException(APDUResponse.StatusWord status) => SW = status;
        public APDUException(string message, APDUResponse.StatusWord status) : base(message) => SW = status;
        public APDUException(string message, APDUResponse.StatusWord status, Exception inner) : base(message, inner) => SW = status;
    }

    public class ModeSwitchException : APDUException
    {
        public ModeSwitchException() { }
        public ModeSwitchException(string message) : base(message) { }
        public ModeSwitchException(string message, Exception inner) : base(message, inner) { }
        public ModeSwitchException(APDUResponse.StatusWord status) => SW = status;
        public ModeSwitchException(string message, APDUResponse.StatusWord status) : base(message) => SW = status;
        public ModeSwitchException(string message, APDUResponse.StatusWord status, Exception inner) : base(message, inner) => SW = status;
    }

    public class UnexpectedResponseException : APDUException
    {
        public UnexpectedResponseException() { }
        public UnexpectedResponseException(string message) : base(message) { }
        public UnexpectedResponseException(string message, Exception inner) : base(message, inner) { }
        public UnexpectedResponseException(APDUResponse.StatusWord status) => SW = status;
        public UnexpectedResponseException(string message, APDUResponse.StatusWord status) : base(message) => SW = status;
        public UnexpectedResponseException(string message, APDUResponse.StatusWord status, Exception inner) : base(message, inner) => SW = status;
    }

    public class ConnectionException : APDUException
    {
        public ConnectionException() { }
        public ConnectionException(string message) : base(message) { }
        public ConnectionException(string message, Exception inner) : base(message, inner) { }
        public ConnectionException(APDUResponse.StatusWord status) => SW = status;
        public ConnectionException(string message, APDUResponse.StatusWord status) : base(message) => SW = status;
        public ConnectionException(string message, APDUResponse.StatusWord status, Exception inner) : base(message, inner) => SW = status;
    }

    public class KeyExistsException : APDUException
    {
        public KeyExistsException() { }
        public KeyExistsException(string message) : base(message) { }
        public KeyExistsException(string message, Exception inner) : base(message, inner) { }
        public KeyExistsException(APDUResponse.StatusWord status) => SW = status;
        public KeyExistsException(string message, APDUResponse.StatusWord status) : base(message) => SW = status;
        public KeyExistsException(string message, APDUResponse.StatusWord status, Exception inner) : base(message, inner) => SW = status;
    }
}
