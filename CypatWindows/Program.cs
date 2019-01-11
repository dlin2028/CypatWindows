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
using System.Security.AccessControl;
using System.DirectoryServices;

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
                    //ExecuteCommand("dism /online /disable-feature /featurename:" + line);
                }
            }
            #endregion

            Console.WriteLine("flushing dns");
            ExecuteCommand("ipconfig /flushdns");

            Console.WriteLine("setting password age");
            ExecuteCommand("net accounts /minpwlen:10");
            ExecuteCommand("net accounts /minpwage:5");
            ExecuteCommand("net accounts /maxpwage:30");

            Console.WriteLine(@"Deleting media files in C:\Users");
            Console.WriteLine("OWNING COMPUTER");
            ExecuteCommand("icacls " + @"C:\Users" + " /setowner \"Administrators\" /T /C");
            
            #region users
            {
                string[] admins = File.ReadAllLines(@"admins.txt");
                string[] standards = File.ReadAllLines(@"standards.txt");
                string[] combined = admins.Concat(standards).ToArray();

                DirectoryEntry localDirectory = new DirectoryEntry("WinNT://" + Environment.MachineName.ToString());
                DirectoryEntries users = localDirectory.Children;


                List<string> unauthorizedUsers = GetComputerUsers();
                foreach (var userName in combined)
                {
                    Console.WriteLine($"Found authorized user {userName}");
                    unauthorizedUsers.Remove(userName);
                }

                foreach (var unauthorizedUser in unauthorizedUsers)
                {
                    try
                    {
                        Console.WriteLine($"Press enter to remove unauthorized user {unauthorizedUser}");
                        Console.ReadKey();
                        DirectoryEntry user = users.Find(unauthorizedUser);
                        users.Remove(user);
                        Console.WriteLine($"Removed unauthorized user {unauthorizedUser}");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"failed to remove unauthorized user {unauthorizedUser}");
                        Console.WriteLine(e.ToString());
                    }
                }

                foreach (var userName in admins)
                {
                    try
                    {
                        DirectoryEntry user = users.Find(userName);
                        Console.WriteLine($"Found admin {userName}");
                    }
                    catch
                    {
                        DirectoryEntry AD = new DirectoryEntry("WinNT://" +
                                       Environment.MachineName + ",computer");
                        DirectoryEntry NewUser = AD.Children.Add(userName, "user");
                        NewUser.Invoke("SetPassword", new object[] { "Exploratory123$" });
                        NewUser.Invoke("Put", new object[] { "Description", "admin user added by script" });
                        NewUser.CommitChanges();
                        DirectoryEntry grp;

                        grp = AD.Children.Find("Administrators", "group");
                        if (grp != null) { grp.Invoke("Add", new object[] { NewUser.Path.ToString() }); }
                        Console.WriteLine($"Admin account {userName} Created Successfully");
                        Console.WriteLine($"Password: Exploratory123$");
                    }
                }


                foreach (var userName in standards)
                {
                    try
                    {
                        DirectoryEntry user = users.Find(userName);
                        Console.WriteLine($"Found standard user {userName}");
                    }
                    catch
                    {
                        DirectoryEntry AD = new DirectoryEntry("WinNT://" +
                                       Environment.MachineName + ",computer");
                        DirectoryEntry NewUser = AD.Children.Add(userName, "user");
                        NewUser.Invoke("SetPassword", new object[] { "Exploratory123$" });
                        NewUser.Invoke("Put", new object[] { "Description", "standard user added by script" });
                        NewUser.CommitChanges();
                        DirectoryEntry grp;

                        grp = AD.Children.Find("Users", "group");
                        if (grp != null) { grp.Invoke("Add", new object[] { NewUser.Path.ToString() }); }
                        Console.WriteLine($"Standard account {userName} Created Successfully");
                        Console.WriteLine($"Password: Exploratory123$");
                    }
                }

            }
            #endregion



            Console.ReadKey();
        }

        public static List<string> GetComputerUsers()
        {
            List<string> users = new List<string>();
            var path =
                string.Format("WinNT://{0},computer", Environment.MachineName);

            using (var computerEntry = new DirectoryEntry(path))
                foreach (DirectoryEntry childEntry in computerEntry.Children)
                    if (childEntry.SchemaClassName == "User")
                        users.Add(childEntry.Name);

            return users;
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

        static void ExecuteCommand(string command, bool block = false)
        {
            int exitCode;
            ProcessStartInfo processInfo;
            Process process;

            processInfo = new ProcessStartInfo("cmd.exe", "/c " + command);
            
            process = Process.Start(processInfo);
            while(!process.HasExited && block)
            {

            }
            process.Close();
        }

        private static void AddFiles(string path, IList<string> files)
        {
            try
            {
                Directory.GetFiles(path)
                    .ToList()
                    .ForEach(s => files.Add(s));

                Directory.GetDirectories(path)
                    .ToList()
                    .ForEach(s => AddFiles(s, files));
            }
            catch (UnauthorizedAccessException ex)
            {
                // ok, so we are not allowed to dig into that directory. Move on.
            }
        }
    }
}
