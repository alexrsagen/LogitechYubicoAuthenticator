using System;
using System.Threading;
using System.Drawing;
using System.Text;
using System.Collections.Generic;
using System.Collections.Concurrent;
using GammaJul.LgLcd;
using YubicoCCID;
using System.Windows.Forms;

namespace LogitechYubicoAuthenticator
{
    class LogitechYubicoAuthenticator
    {
        private struct ListState<T>
        {
            public object Lock;
            public int Selected;
            public int Offset;
            public bool Changed;
            public T Items;
        }

        private enum Action : byte
        {
            Connect
        }

        private static ListState<string[]> devicesList = new ListState<string[]>();
        private static ListState<List<OATHController.Credential>> entriesList = new ListState<List<OATHController.Credential>>();
        private static OATHController.Code? entryCode;
        private static bool entryCodeRequested;

        private static ConcurrentBag<Action> actions = new ConcurrentBag<Action>();

        private static Dictionary<string, uint> timers = new Dictionary<string, uint>();

        private static readonly object deviceArrivedLock = new object();
        private static bool deviceArrived = false;
        
        private static CCIDDriver ccid = null;
        private static OATHController oath = null;
        
        [MTAThread]
        internal static void Main(string[] args)
        {
            Application.EnableVisualStyles();

            devicesList.Lock = new object();
            entriesList.Lock = new object();

            LcdApplet applet = new LcdApplet("Yubico Authenticator", LcdAppletCapabilities.Monochrome);

            // Register to events to know when a device arrives, then connects the applet to the LCD Manager
            applet.Configure += AppletConfigure;
            applet.DeviceArrival += AppletDeviceArrival;
            applet.DeviceRemoval += AppletDeviceRemoval;
            applet.IsEnabledChanged += AppletIsEnableChanged;
            applet.Connect();

            LcdDeviceMonochrome device = null;
            int tick = 0;

            while (true)
            {
                lock(deviceArrivedLock)
                {
                    if (deviceArrived)
                    {
                        if (device == null)
                        {
                            device = (LcdDeviceMonochrome)applet.OpenDeviceByType(LcdDeviceType.Monochrome);
                            device.SoftButtonsChanged += DeviceSoftButtonsChanged;
                            CreatePages(device);
                            device.SetAsForegroundApplet = true;
                        }
                        else
                        {
                            device.ReOpen();
                        }
                    }

                    deviceArrived = false;
                }

                if (applet.IsEnabled && device != null && !device.IsDisposed)
                    device.DoUpdateAndDraw();
                
                TickTimers(33, ref tick);
                Thread.Sleep(33);
            }
        }

        /// <summary>
        /// Creates a timer based on the frame count and FPS of screen rendering, not very accurate but works.
        /// </summary>
        /// <param name="name">Timer name</param>
        /// <param name="duration">Timer duration</param>
        private static void CreateTimer(string name, uint duration)
        {
            timers[name] = duration;
        }

        /// <summary>
        /// Clears a timer.
        /// </summary>
        /// <param name="name">Timer name</param>
        private static void ClearTimer(string name)
        {
            timers.Remove(name);
        }

        /// <summary>
        /// Checks if a timer is done.
        /// </summary>
        /// <param name="name"></param>
        /// <returns>Returns true if the timer is done.</returns>
        private static bool CheckTimer(string name)
        {
            if (timers.ContainsKey(name) && timers[name] == 0)
            {
                ClearTimer(name);
                return true;
            }

            return false;
        }

        /// <summary>
        /// Updates all timers based on a tickrate and current tick.
        /// </summary>
        /// <param name="tickrate">Rate at which ticks happen (in milliseconds)</param>
        /// <param name="tick">Current tick counter</param>
        private static void TickTimers(int tickrate, ref int tick)
        {
            if (tickrate * tick >= 990)
            {
                tick = 0;
                List<string> keys = new List<string>(timers.Keys);
                foreach (string key in keys)
                    if (timers[key] > 0)
                        timers[key]--;
            }
            tick++;
        }

        /// <summary>
        /// Increments the <see cref="ListState{T}.Selected"/> property
        /// </summary>
        /// <param name="list">The <see cref="ListState{T}"/> to increment selector of</param>
        /// <param name="items">The amount of items to show in the list</param>
        private static void IncrementListState(ref ListState<string[]> list, int items)
        {
            if (list.Lock == null)
                throw new ArgumentException("The list lock is not initialized", "list");

            lock (list.Lock)
            {
                if (list.Items != null && list.Selected < list.Items.Length - 1)
                {
                    list.Changed = true;
                    list.Selected++;
                    if (list.Selected >= list.Offset + items)
                    {
                        list.Offset++;
                    }
                }
            }
        }

        /// <summary>
        /// Increments the <see cref="ListState{T}.Selected"/> property
        /// </summary>
        /// <param name="list">The <see cref="ListState{T}"/> to increment selector of</param>
        /// <param name="items">The amount of items to show in the list</param>
        private static void IncrementListState(ref ListState<List<OATHController.Credential>> list, int items)
        {
            if (list.Lock == null)
                throw new ArgumentException("The list lock is not initialized", "list");

            lock (list.Lock)
            {
                if (list.Items != null && list.Selected < list.Items.Count - 1)
                {
                    list.Changed = true;
                    list.Selected++;
                    if (list.Selected >= list.Offset + items)
                    {
                        list.Offset++;
                    }
                }
            }
        }

        /// <summary>
        /// Decrements the <see cref="ListState{T}.Selected"/> property>.
        /// </summary>
        /// <param name="list">The <see cref="ListState{T}"/> to decrement selector of</param>
        private static void DecrementListState<T>(ref ListState<T> list)
        {
            if (list.Lock == null)
                throw new ArgumentException("The list lock is not initialized", "list");

            lock (list.Lock)
            {
                if (list.Items != null && list.Selected > 0)
                {
                    list.Changed = true;
                    list.Selected--;
                    if (list.Selected < list.Offset)
                    {
                        list.Offset--;
                    }
                }
            }
        }

        /// <summary>
        /// Prompts for a password in the console.
        /// </summary>
        /// <param name="mask">Password mask</param>
        /// <returns>Returns the entered password.</returns>
        private static string ConsolePromptPassword(char mask = '*')
        {
            Console.Write("Password: ");
            StringBuilder sb = new StringBuilder();
            ConsoleKeyInfo cki = Console.ReadKey(true);
            while (cki.Key != ConsoleKey.Enter)
            {
                if (cki.Key == ConsoleKey.Backspace && sb.Length > 0)
                {
                    sb.Remove(sb.Length - 1, 1);
                    Console.Write("\rPassword: " + new string(' ', sb.Length + 1) + "\rPassword: " + new string('*', sb.Length));
                }
                else if (cki.KeyChar > 31 && cki.KeyChar < 127 || cki.KeyChar > 127)
                {
                    sb.Append(cki.KeyChar);
                    Console.Write(mask);
                }
                cki = Console.ReadKey(true);
            }
            Console.Write("\n");

            return sb.ToString();
        }

        /// <summary>
        /// Creates default state of pages on the device.
        /// </summary>
        /// <param name="device">Logitech LCD device</param>
        private static void CreatePages(LcdDeviceMonochrome device)
        {
            // LCD Resolution = 160x43

            LcdGdiPage pageDevices = new LcdGdiPage(device);
            pageDevices.Updating += UpdateDevicePage;
            device.Pages.Add(pageDevices);

            LcdGdiPage pageConnectionStatus = new LcdGdiPage(device)
            {
                Children =
                {
                    new LcdGdiImage
                    {
                        Image = Properties.Resources.Refresh,
                        Margin = new MarginF(97.0f, 33.0f, 0.0f, 0.0f),
                        IsVisible = false
                    },
                    new LcdGdiImage
                    {
                        Image = Properties.Resources.Back,
                        Margin = new MarginF(138.0f, 33.0f, 0.0f, 0.0f),
                        IsVisible = false
                    },
                    new LcdGdiRectangle
                    {
                        Size = new SizeF(160.0f, 12.0f),
                        Brush = Brushes.Black
                    },
                    new LcdGdiScrollViewer
                    {
                        Child = new LcdGdiText
                        {
                            Brush = Brushes.White
                        },
                        Margin = new MarginF(0.0f, 0.0f, 0.0f, 0.0f),
                        HorizontalAlignment = LcdGdiHorizontalAlignment.Stretch,
                        VerticalAlignment = LcdGdiVerticalAlignment.Stretch,
                        AutoScrollX = true
                    },
                    new LcdGdiText
                    {
                        Margin = new MarginF(0.0f, 12.0f, 0.0f, 0.0f)
                    }
                }
            };
            pageConnectionStatus.Updating += UpdateConnectionStatusPage;
            device.Pages.Add(pageConnectionStatus);

            LcdGdiPage pageEntries = new LcdGdiPage(device);
            pageEntries.Updating += UpdateEntriesPage;
            device.Pages.Add(pageEntries);

            LcdGdiPage pageEntry = new LcdGdiPage(device)
            {
                Children =
                {
                    new LcdGdiImage
                    {
                        Image = Properties.Resources.Refresh,
                        Margin = new MarginF(97.0f, 33.0f, 0.0f, 0.0f),
                        IsVisible = false
                    },
                    new LcdGdiImage
                    {
                        Image = Properties.Resources.Back,
                        Margin = new MarginF(138.0f, 33.0f, 0.0f, 0.0f)
                    },
                    new LcdGdiProgressBar
                    {
                        Margin = new MarginF(0.0f, 28.0f, 0.0f, 0.0f),
                        Size = new SizeF(160.0f, 5.0f),
                        Brush = Brushes.White,
                        ProgressBrush = Brushes.Black,
                        Minimum = 0,
                        Maximum = 100,
                        Value = 50,
                        IsVisible = false
                    },
                    new LcdGdiRectangle
                    {
                        Size = new SizeF(160.0f, 12.0f),
                        Brush = Brushes.Black
                    },
                    new LcdGdiScrollViewer
                    {
                        Child = new LcdGdiText
                        {
                            Brush = Brushes.White
                        },
                        Margin = new MarginF(0.0f, 0.0f, 0.0f, 0.0f),
                        HorizontalAlignment = LcdGdiHorizontalAlignment.Stretch,
                        VerticalAlignment = LcdGdiVerticalAlignment.Stretch,
                        AutoScrollX = true
                    },
                    new LcdGdiText
                    {
                        Margin = new MarginF(0.0f, 11.0f, 0.0f, 0.0f),
                        Font = new Font(FontFamily.GenericSansSerif, 11.0f)
                    }
                }
            };
            pageEntry.Updating += UpdateEntryPage;
            device.Pages.Add(pageEntry);

            pageDevices.SetAsCurrentDevicePage();
        }

        /// <summary>
        /// Updates the device selection page before rendering it.
        /// </summary>
        /// <param name="sender">Page being updated</param>
        /// <param name="e">Update event arguments</param>
        private static void UpdateDevicePage(object sender, UpdateEventArgs e)
        {
            LcdGdiPage page = (LcdGdiPage)sender;

            lock (devicesList.Lock)
            {
                // Update list items
                string[] newItems = CCIDDriver.ListReaders();
                if (!newItems.Equals(devicesList.Items))
                    devicesList.Changed = true;

                if (!devicesList.Changed)
                    return;

                page.Children.Clear();
                devicesList.Items = newItems;

                if (devicesList.Items == null || devicesList.Items.Length == 0)
                {
                    page.Children.Add(new LcdGdiText
                    {
                        Text = "No YubiKey detected.",
                        Margin = new MarginF(0.0f, 0.0f, 0.0f, 0.0f),
                        Font = new Font(FontFamily.GenericSansSerif, 7.0f, FontStyle.Underline)
                    });
                }
                else
                {
                    // Update list selected state based on new items
                    while (devicesList.Selected >= devicesList.Items.Length && devicesList.Selected > 0)
                        devicesList.Selected--;

                    // Add button icons
                    page.Children.Add(new LcdGdiImage
                    {
                        Image = Properties.Resources.ArrowUP,
                        Margin = new MarginF(12.0f, 33.0f, 0.0f, 0.0f)
                    });
                    page.Children.Add(new LcdGdiImage
                    {
                        Image = Properties.Resources.ArrowDN,
                        Margin = new MarginF(55.0f, 33.0f, 0.0f, 0.0f)
                    });
                    page.Children.Add(new LcdGdiImage
                    {
                        Image = Properties.Resources.Check,
                        Margin = new MarginF(97.0f, 33.0f, 0.0f, 0.0f)
                    });

                    // Add list items
                    for (int i = devicesList.Offset, j = 0; i < devicesList.Items.Length && j < 3; i++, j++)
                    {
                        if (i == devicesList.Selected)
                            page.Children.Add(new LcdGdiRectangle(Brushes.Black, new RectangleF(0.0f, j * 11.0f, 161.0f, 12.0f)));

                        page.Children.Add(new LcdGdiScrollViewer
                        {
                            Child = new LcdGdiText
                            {
                                Text = devicesList.Items[i],
                                Brush = i == devicesList.Selected ? Brushes.White : Brushes.Black
                            },
                            Margin = new MarginF(0.0f, j * 11.0f, 0.0f, 0.0f),
                            HorizontalAlignment = LcdGdiHorizontalAlignment.Stretch,
                            VerticalAlignment = LcdGdiVerticalAlignment.Stretch,
                            AutoScrollX = i == devicesList.Selected
                        });
                    }
                }
            }
        }

        /// <summary>
        /// Updates the connection status page before rendering it.
        /// </summary>
        /// <param name="sender">Page being updated</param>
        /// <param name="e">Update event arguments</param>
        private static void UpdateConnectionStatusPage(object sender, UpdateEventArgs e)
        {
            LcdGdiPage page = (LcdGdiPage)sender;
            LcdGdiImage refreshButton = (LcdGdiImage)page.Children[0];
            LcdGdiImage backButton = (LcdGdiImage)page.Children[1];
            LcdGdiScrollViewer deviceScrollView = (LcdGdiScrollViewer)page.Children[3];
            LcdGdiText deviceText = (LcdGdiText)deviceScrollView.Child;
            LcdGdiText statusText = (LcdGdiText)page.Children[4];

            if (oath != null && oath.HasChallenge())
            {
                using (var dialog = new PasswordDialog())
                {
                    dialog.OKButton.Click += (_sender, _e) =>
                    {
                        try
                        {
                            oath.Validate(dialog.PasswordBox.Text);
                            statusText.Text = "Connected.";
                            CreateTimer("ConnectionStatusSwitchPage", 2);
                        }
                        catch (UnexpectedResponseException)
                        {
                            statusText.Text = "Invalid password, try again...";
                        }
                        dialog.Close();
                    };
                    dialog.CancelButton.Click += (_sender, _e) =>
                    {
                        oath = null;
                        ccid = null;
                        page.Device.Pages[0].SetAsCurrentDevicePage();
                        dialog.Close();
                    };
                    dialog.ShowDialog();
                }
            }

            if (CheckTimer("ConnectionStatusSwitchPage"))
            {
                // Update list items
                lock (entriesList.Lock)
                {
                    entriesList.Items = oath.List();
                    entriesList.Changed = true;

                    // Calculate all keys and update touch info
                    var codes = oath.CalculateAll();
                    foreach (var code in codes)
                    {
                        if (code.Credential.Touch)
                        {
                            var idx = entriesList.Items.FindIndex(item => item.Name.Equals(code.Credential.Name));
                            if (idx != -1)
                            {
                                var item = entriesList.Items[idx];
                                item.Touch = code.Credential.Touch;
                                entriesList.Items[idx] = item;
                            }
                        }
                    }
                }

                // Switch page
                page.Device.Pages[2].SetAsCurrentDevicePage();
                return;
            }

            lock(devicesList.Lock)
            {
                while (actions.TryTake(out Action a))
                {
                    switch (a)
                    {
                        case Action.Connect:
                            try
                            {
                                ccid = CCIDDriver.OpenDevice(devicesList.Items[devicesList.Selected]);
                                oath = new OATHController(ccid);
                                deviceText.Text = devicesList.Items[devicesList.Selected];
                                backButton.IsVisible = false;
                                refreshButton.IsVisible = false;

                                if (oath.HasChallenge())
                                {
                                    statusText.Text = "Waiting for password...";
                                }
                                else
                                {
                                    statusText.Text = "Connected.";
                                    CreateTimer("ConnectionStatusSwitchPage", 2);
                                }
                            }
                            catch (ConnectionException)
                            {
                                oath = null;
                                ccid = null;
                                deviceText.Text = devicesList.Items[devicesList.Selected];
                                statusText.Text = "Unable to connect.";
                                backButton.IsVisible = true;
                                refreshButton.IsVisible = true;
                            }
                            break;
                    }
                }
            }
        }

        /// <summary>
        /// Updates the entries page before rendering it.
        /// </summary>
        /// <param name="sender">Page being updated</param>
        /// <param name="e">Update event arguments</param>
        private static void UpdateEntriesPage(object sender, UpdateEventArgs e)
        {
            LcdGdiPage page = (LcdGdiPage)sender;

            lock (entriesList.Lock)
            {
                if (!entriesList.Changed)
                    return;

                entriesList.Changed = false;
                page.Children.Clear();

                if (entriesList.Items == null || entriesList.Items.Count == 0)
                {
                    page.Children.Add(new LcdGdiText
                    {
                        Text = "YubiKey has no entries.",
                        Margin = new MarginF(0.0f, 0.0f, 0.0f, 0.0f),
                        Font = new Font(FontFamily.GenericSansSerif, 7.0f, FontStyle.Underline)
                    });
                }
                else
                {
                    // Update list selected state based on new items
                    while (entriesList.Selected >= entriesList.Items.Count && entriesList.Selected > 0)
                        entriesList.Selected--;

                    // Add button icons
                    page.Children.Add(new LcdGdiImage
                    {
                        Image = Properties.Resources.ArrowUP,
                        Margin = new MarginF(12.0f, 33.0f, 0.0f, 0.0f)
                    });
                    page.Children.Add(new LcdGdiImage
                    {
                        Image = Properties.Resources.ArrowDN,
                        Margin = new MarginF(55.0f, 33.0f, 0.0f, 0.0f)
                    });
                    page.Children.Add(new LcdGdiImage
                    {
                        Image = Properties.Resources.Check,
                        Margin = new MarginF(97.0f, 33.0f, 0.0f, 0.0f)
                    });
                    page.Children.Add(new LcdGdiImage
                    {
                        Image = Properties.Resources.Back,
                        Margin = new MarginF(138.0f, 33.0f, 0.0f, 0.0f)
                    });

                    // Add list items
                    for (int i = entriesList.Offset, j = 0; i < entriesList.Items.Count && j < 3; i++, j++)
                    {
                        if (i == entriesList.Selected)
                            page.Children.Add(new LcdGdiRectangle(Brushes.Black, new RectangleF(0.0f, j * 11.0f, 161.0f, 12.0f)));

                        page.Children.Add(new LcdGdiScrollViewer
                        {
                            Child = new LcdGdiText
                            {
                                Text = entriesList.Items[i].Issuer + " | " + entriesList.Items[i].Account,
                                Brush = i == entriesList.Selected ? Brushes.White : Brushes.Black
                            },
                            Margin = new MarginF(0.0f, j * 11.0f, 0.0f, 0.0f),
                            HorizontalAlignment = LcdGdiHorizontalAlignment.Stretch,
                            VerticalAlignment = LcdGdiVerticalAlignment.Stretch,
                            AutoScrollX = i == entriesList.Selected
                        });
                    }
                }
            }
        }

        /// <summary>
        /// Updates the code page before rendering it.
        /// </summary>
        /// <param name="sender">Page being updated</param>
        /// <param name="e">Update event arguments</param>
        private static void UpdateEntryPage(object sender, UpdateEventArgs e)
        {
            LcdGdiPage page = (LcdGdiPage)sender;
            LcdGdiImage refreshIcon = (LcdGdiImage)page.Children[0];
            LcdGdiProgressBar progressBar = (LcdGdiProgressBar)page.Children[2];
            LcdGdiScrollViewer scrollView = (LcdGdiScrollViewer)page.Children[4];
            LcdGdiText textName = (LcdGdiText)scrollView.Child;
            LcdGdiText textCode = (LcdGdiText)page.Children[5];

            lock (entriesList.Lock)
            {
                progressBar.IsVisible = false;

                if (!entryCodeRequested && !entryCode.HasValue)
                {
                    textName.Text = entriesList.Items[entriesList.Selected].Name;
                    entryCodeRequested = true;

                    if (entriesList.Items[entriesList.Selected].Touch)
                    {
                        textCode.Text = "Touch your YubiKey...";
                        refreshIcon.IsVisible = false;
                        return;
                    }
                }
                entryCodeRequested = false;

                DateTime time = DateTime.UtcNow;
                Int32 timestamp = (Int32)(time.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
                if (!entryCode.HasValue || entryCode.Value.ValidTo != 0 && entryCode.Value.ValidTo < timestamp && entriesList.Items[entriesList.Selected].Type == OATHController.Type.TOTP && !entriesList.Items[entriesList.Selected].Touch)
                {
                    try
                    {
                        entryCode = oath.Calculate(entriesList.Items[entriesList.Selected], time);
                        textCode.Text = entryCode.Value.Value;
                    }
                    catch (UnexpectedResponseException ex)
                    {
                        entryCode = new OATHController.Code(); // Hack: Set empty code object to prevent code regen
                        if (ex.SW == APDUResponse.StatusWord.AUTH_REQUIRED)
                        {
                            textCode.Text = "Touch timeout.";
                        }
                        else
                        {
                            textCode.Text = "Error: " + ex.SW.ToString();
                        }
                        refreshIcon.IsVisible = true;
                        return;
                    }
                }

                if (entriesList.Items[entriesList.Selected].Type == OATHController.Type.TOTP && entryCode.HasValue && entryCode.Value.ValidTo != 0)
                {
                    if (entryCode.Value.ValidTo > timestamp)
                    {
                        progressBar.IsVisible = true;
                        progressBar.Value = (int)(((float)(entryCode.Value.ValidTo - timestamp) / entriesList.Items[entriesList.Selected].Period) * 100);
                    }
                    else if (entriesList.Items[entriesList.Selected].Touch)
                    {
                        textCode.Text = "Code expired.";
                        progressBar.IsVisible = false;
                        refreshIcon.IsVisible = true;
                    }
                }
            }
        }

        /// <summary>
        /// Event handler for new device arrival in the system.
        /// Monochrome devices include (G510, G13, G15, Z10).
        /// </summary>
        /// <param name="sender">Applet or device?</param>
        /// <param name="e">Device type event arguments</param>
        private static void AppletDeviceArrival(object sender, LcdDeviceTypeEventArgs e)
        {
            switch (e.DeviceType)
            {
                // A monochrome device (G13/G15/Z10) was connected
                case LcdDeviceType.Monochrome:
                    lock(deviceArrivedLock)
                        deviceArrived = true;
                    break;
                default:
                    break;
            }
        }

        /// <summary>
        /// Event handler for Configure button click (for this applet) in the LCD Manager.
        /// </summary>
        /// <param name="sender">Applet?</param>
        /// <param name="e">Event arguments</param>
        private static void AppletConfigure(object sender, EventArgs e)
        {
            // No action required
        }

        /// <summary>
        /// Event handler for device removal.
        /// </summary>
        /// <param name="sender">Applet?</param>
        /// <param name="e">Event arguments</param>
        private static void AppletDeviceRemoval(object sender, LcdDeviceTypeEventArgs e)
        {
            // No action required
        }

        /// <summary>
        /// Event handler for applet enable or disable in the LCD Manager.
        /// </summary>
        /// <param name="sender">Applet?</param>
        /// <param name="e">Event arguments</param>
        private static void AppletIsEnableChanged(object sender, EventArgs e)
        {
            // No action required
        }

        private static bool button0Up = true;
        private static bool button1Up = true;
        private static bool button2Up = true;
        private static bool button3Up = true;

        /// <summary>
        /// Event handler for button press on a device.
        /// </summary>
        /// <param name="sender">Device on which button was pressed</param>
        /// <param name="e">Button event arguments</param>
        private static void DeviceSoftButtonsChanged(object sender, LcdSoftButtonsEventArgs e)
        {
            LcdDeviceMonochrome device = (LcdDeviceMonochrome)sender;

            // First button 
            if ((e.SoftButtons & LcdSoftButtons.Button0) == LcdSoftButtons.Button0)
            {
                if (button0Up)
                {
                    button0Up = false;

                    if (device.CurrentPage == device.Pages[0])
                    {
                        DecrementListState(ref devicesList);
                    }
                    else if (device.CurrentPage == device.Pages[2])
                    {
                        DecrementListState(ref entriesList);
                    }
                }
            }
            else
            {
                button0Up = true;
            }

            // Second button 
            if ((e.SoftButtons & LcdSoftButtons.Button1) == LcdSoftButtons.Button1)
            {
                if (button1Up)
                {
                    button1Up = false;

                    if (device.CurrentPage == device.Pages[0])
                    {
                        IncrementListState(ref devicesList, 3);
                    }
                    else if (device.CurrentPage == device.Pages[2])
                    {
                        IncrementListState(ref entriesList, 3);
                    }
                }
            }
            else
            {
                button1Up = true;
            }

            // Third button 
            if ((e.SoftButtons & LcdSoftButtons.Button2) == LcdSoftButtons.Button2)
            {
                if (button2Up)
                {
                    button2Up = false;

                    if (device.CurrentPage == device.Pages[0])
                    {
                        lock (devicesList.Lock)
                        {
                            if (devicesList.Items != null && devicesList.Items.Length > 0)
                            {
                                actions.Add(Action.Connect);
                                device.Pages[1].SetAsCurrentDevicePage();
                            }
                        }
                    }
                    else if (device.CurrentPage == device.Pages[1] && ccid == null)
                    {
                        actions.Add(Action.Connect);
                    }
                    else if (device.CurrentPage == device.Pages[2])
                    {
                        lock (entriesList.Lock)
                        {
                            if (entryCode.HasValue && !entryCode.Value.Credential.Name.Equals(entriesList.Items[entriesList.Selected].Name))
                            {
                                // Reset code object
                                entryCode = null;

                                // Reset text elements
                                LcdGdiPage page = (LcdGdiPage)device.Pages[3];
                                LcdGdiScrollViewer scrollView = (LcdGdiScrollViewer)page.Children[4];
                                LcdGdiText textName = (LcdGdiText)scrollView.Child;
                                LcdGdiText textCode = (LcdGdiText)page.Children[5];
                                textName.Text = null;
                                textCode.Text = null;
                            }
                        }

                        device.Pages[3].SetAsCurrentDevicePage();
                    }
                    else if (device.CurrentPage == device.Pages[3])
                    {
                        lock (entriesList.Lock)
                        {
                            LcdGdiPage page = (LcdGdiPage)device.Pages[3];
                            LcdGdiImage refreshIcon = (LcdGdiImage)page.Children[0];

                            if (refreshIcon.IsVisible)
                            {
                                entryCode = null;
                            }
                        }
                    }
                }
            }
            else
            {
                button2Up = true;
            }

            // Fourth button 
            if ((e.SoftButtons & LcdSoftButtons.Button3) == LcdSoftButtons.Button3)
            {
                if (button3Up)
                {
                    button3Up = false;

                    if (device.CurrentPage == device.Pages[1] || device.CurrentPage == device.Pages[2])
                    {
                        device.Pages[0].SetAsCurrentDevicePage();
                    }
                    else if (device.CurrentPage == device.Pages[3])
                    {
                        device.Pages[2].SetAsCurrentDevicePage();
                    }
                }
            }
            else
            {
                button3Up = true;
            }
        }
    }
}
