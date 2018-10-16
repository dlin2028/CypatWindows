using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using WindowsFirewallHelper;
using System.Security.Policy;
using System.Collections.ObjectModel;
using Microsoft.Win32;
using System.IO;
using System.Text.RegularExpressions;
using System.Reflection;
using System.Diagnostics;

namespace CypatWindows
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("----------FIREWALL-----------");
            #region firewall
            SetFirewallRule("Remote Assistance (DCOM-In)", false);
            SetFirewallRule("Remote Assistance (PNRP-In)", false);
            SetFirewallRule("Remote Assistance (RA Server TCP-In)", false);
            SetFirewallRule("Remote Assistance (SSDP TCP-In)", false);
            SetFirewallRule("Remote Assistance (SSDP UDP-In)", false);
            SetFirewallRule("Remote Assistance (TCP-In)", false);
            SetFirewallRule("Telnet Server", false);
            SetFirewallRule("netcat", false);
            #endregion


            Console.WriteLine("----------REGISTRIES-----------");
            #region reg
            {
                string[] lines = File.ReadAllLines(@"regkeys.txt");
                foreach (var line in lines)
                {
                    string[] words = Regex.Split(line, "(?<=^[^\"]*(?:\"[^\"]*\"[^\"]*)*) (?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");

                    SetRegistry(words[0].Replace("\"", ""), words[1], words[2], words[3]);
                }
            }
            #endregion

            #region features
            {
                string[] lines = File.ReadAllLines(@"features.txt");
                foreach (var line in lines)
                {
                    Console.WriteLine("Disabling " + line);
                    ExecuteCommand("dism /online /disable-feature /featurename:" + line);
                }
            }
            #endregion

            Console.ReadKey();
        }

        static void SetFirewallRule(string name, bool enabled)
        {
            Console.WriteLine($"setting {name} to {enabled}");
            var rule = FirewallManager.Instance.Rules.FirstOrDefault((x) => x.Name == name);
            if (rule == null)
            {
                Console.WriteLine($"ERROR: RULE {name} DOES NOT EXIST ");
                return;
            }
            FirewallManager.Instance.Rules.FirstOrDefault((x) => x.Name == name).IsEnable = enabled;
        }
        
        static void SetRegistry(string key, string name, string type /* type isn't used rn */, string value)
        {
            Console.WriteLine($"setting {key}");
            RegistryKey myKey;
            if (key.Contains("HKLM"))
            {
                myKey = Registry.LocalMachine.OpenSubKey(key.Substring(5), true);
                if (myKey == null)
                {
                    Console.WriteLine($"key not found, attempting to create {key}");
                    myKey = Registry.LocalMachine.CreateSubKey(key.Substring(5), true);
                }
            }
            else
            {
                myKey = Registry.CurrentUser.OpenSubKey(key.Substring(5), true);
                if (myKey == null)
                {
                    Console.WriteLine($"key not found, attempting to create {key}");
                    myKey = Registry.CurrentUser.CreateSubKey(key.Substring(5), true);
                }
            }
            if (myKey == null)
            {
            }
            myKey.SetValue(name, value, RegistryValueKind.DWord);
            myKey.Close();
            Console.WriteLine($"succ {key}");
        }

        static void SetGroupPolicy()
        {
            //WinAPIForGroupPolicy.
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="command"></param>
        static void ExecuteCommand(string command)
        {
            int exitCode;
            ProcessStartInfo processInfo;
            Process process;

            processInfo = new ProcessStartInfo("cmd.exe", "/c " + command);
            
            process = Process.Start(processInfo);

            process.Close();
        }
    }
}
