using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
namespace CypatWindows
{
    /// <summary>
    /// Represent the result of group policy operations.
    /// </summary>
    public enum ResultCode
    {
        Succeed = 0,
        CreateOrOpenFailed = -1,
        SetFailed = -2,
        SaveFailed = -3
    }
    /// <summary>
    /// The WinAPI handler for GroupPlicy operations.
    /// </summary>
    public class WinAPIForGroupPolicy
    {
        // Group Policy Object open / creation flags
        const UInt32 GPO_OPEN_LOAD_REGISTRY = 0x00000001; // Load the registry files
        const UInt32 GPO_OPEN_READ_ONLY = 0x00000002; // Open the GPO as read only
                                                      // Group Policy Object option flags
        const UInt32 GPO_OPTION_DISABLE_USER = 0x00000001; // The user portion of this GPO is disabled
        const UInt32 GPO_OPTION_DISABLE_MACHINE = 0x00000002; // The machine portion of this GPO is disabled
        const UInt32 REG_OPTION_NON_VOLATILE = 0x00000000;
        // You can find the Guid in <Gpedit.h>
        static readonly Guid REGISTRY_EXTENSION_GUID = new Guid("35378EAC-683F-11D2-A89A-00C04FBBCFA2");
        static readonly Guid CLSID_GPESnapIn = new Guid("8FC0B734-A0E1-11d1-A7D3-0000F87571E3");
        /// <summary>
        /// Group Policy Object type.
        /// </summary>
        enum GROUP_POLICY_OBJECT_TYPE
        {
            GPOTypeLocal = 0, // Default GPO on the local machine
            GPOTypeRemote, // GPO on a remote machine
            GPOTypeDS, // GPO in the Active Directory
            GPOTypeLocalUser, // User-specific GPO on the local machine
            GPOTypeLocalGroup // Group-specific GPO on the local machine
        }
        #region COM
        /// <summary>
        /// Group Policy Interface definition from COM.
        /// You can find the Guid in <Gpedit.h>
        /// </summary>
        [Guid("EA502723-A23D-11d1-A7D3-0000F87571E3"),
        InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface IGroupPolicyObject
        {
            void New(
            [MarshalAs(UnmanagedType.LPWStr)] String pszDomainName,
            [MarshalAs(UnmanagedType.LPWStr)] String pszDisplayName,
            UInt32 dwFlags);
            void OpenDSGPO(
            [MarshalAs(UnmanagedType.LPWStr)] String pszPath,
            UInt32 dwFlags);
            void OpenLocalMachineGPO(UInt32 dwFlags);
            void OpenRemoteMachineGPO(
            [MarshalAs(UnmanagedType.LPWStr)] String pszComputerName,
            UInt32 dwFlags);
            void Save(
            [MarshalAs(UnmanagedType.Bool)] bool bMachine,
            [MarshalAs(UnmanagedType.Bool)] bool bAdd,
            [MarshalAs(UnmanagedType.LPStruct)] Guid pGuidExtension,
            [MarshalAs(UnmanagedType.LPStruct)] Guid pGuid);
            void Delete();
            void GetName(
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszName,
            Int32 cchMaxLength);
            void GetDisplayName(
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszName,
            Int32 cchMaxLength);
            void SetDisplayName([MarshalAs(UnmanagedType.LPWStr)] String pszName);
            void GetPath(
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszPath,
            Int32 cchMaxPath);
            void GetDSPath(
            UInt32 dwSection,
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszPath,
            Int32 cchMaxPath);
            void GetFileSysPath(
            UInt32 dwSection,
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszPath,
            Int32 cchMaxPath);
            UInt32 GetRegistryKey(UInt32 dwSection);
            Int32 GetOptions();
            void SetOptions(UInt32 dwOptions, UInt32 dwMask);
            void GetType(out GROUP_POLICY_OBJECT_TYPE gpoType);
            void GetMachineName(
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszName,
            Int32 cchMaxLength);
            UInt32 GetPropertySheetPages(out IntPtr hPages);
        }
        /// <summary>
        /// Group Policy Class definition from COM.
        /// You can find the Guid in <Gpedit.h>
        /// </summary>
        [ComImport, Guid("EA502722-A23D-11d1-A7D3-0000F87571E3")]
        class GroupPolicyObject { }
        #endregion
        #region WinAPI You can find definition of API for C# on: http://pinvoke.net/
        /// <summary>
        /// Opens the specified registry key. Note that key names are not case sensitive.
        /// </summary>
        /// See http://msdn.microsoft.com/en-us/library/ms724897(VS.85).aspx for more info about the parameters.<br/>
        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern Int32 RegOpenKeyEx(
        UIntPtr hKey,
        String subKey,
        Int32 ulOptions,
        RegSAM samDesired,
        out UIntPtr hkResult);
        /// <summary>
        /// enumerate the sub keys according to the given path
        /// </summary>
        [DllImport("advapi32.dll", EntryPoint = "RegEnumKeyEx")]
        public static extern Int32 RegEnumKeyEx(
        UIntPtr hkey,
        UInt32 index,
        StringBuilder lpName,
        ref UInt32 lpcbName,
        IntPtr reserved,
        IntPtr lpClass,
        IntPtr lpcbClass,
        out long lpftLastWriteTime);
        /// <summary>
        /// enumerate the value according to the given path
        /// </summary>
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern uint RegEnumValue(
        UIntPtr hKey,
        UInt32 dwIndex,
        StringBuilder lpValueName,
        ref UInt32 lpcValueName,
        IntPtr lpReserved,
        out UInt32 lpType,
        [Out] byte[] lpData,
        ref UInt32 lpcbData);
        /// <summary>
        /// Retrieves the type and data for the specified value name associated with an open registry key.
        /// </summary>
        /// See http://msdn.microsoft.com/en-us/library/ms724911(VS.85).aspx for more info about the parameters and return value.<br/>
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegQueryValueExW", SetLastError = true)]
        static extern Int32 RegQueryValueEx(
        UIntPtr hKey,
        String lpValueName,
        Int32 lpReserved,
        out UInt32 lpType,
        [Out] byte[] lpData,
        ref UInt32 lpcbData);
        /// <summary>
        /// Sets the data and type of a specified value under a registry key.
        /// </summary>
        /// See http://msdn.microsoft.com/en-us/library/ms724923(VS.85).aspx for more info about the parameters and return value.<br/>
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern Int32 RegSetValueEx(
        UInt32 hKey,
        [MarshalAs(UnmanagedType.LPStr)] String lpValueName,
        Int32 Reserved,
        Microsoft.Win32.RegistryValueKind dwType,
        IntPtr lpData,
        Int32 cbData);
        /// <summary>
        /// Creates the specified registry key. If the key already exists, the function opens it. Note that key names are not case sensitive.
        /// </summary>
        /// See http://msdn.microsoft.com/en-us/library/ms724844(v=VS.85).aspx for more info about the parameters and return value.<br/>
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern Int32 RegCreateKeyEx(
        UInt32 hKey,
        String lpSubKey,
        UInt32 Reserved,
        String lpClass,
        RegOption dwOptions,
        RegSAM samDesired,
        IntPtr lpSecurityAttributes,
        out UInt32 phkResult,
        out RegResult lpdwDisposition);
        /// <summary>
        /// Closes a handle to the specified registry key.
        /// </summary>
        /// See http://msdn.microsoft.com/en-us/library/ms724837(VS.85).aspx for more info about the parameters and return value.<br/>
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern Int32 RegCloseKey(
        UInt32 hKey);
        /// <summary>
        /// Deletes a subkey and its values from the specified platform-specific view of the registry. Note that key names are not case sensitive.
        /// </summary>
        /// See http://msdn.microsoft.com/en-us/library/ms724847(VS.85).aspx for more info about the parameters and return value.<br/>
        [DllImport("advapi32.dll", EntryPoint = "RegDeleteKeyEx", SetLastError = true)]
        public static extern Int32 RegDeleteKeyEx(
        UInt32 hKey,
        String lpSubKey,
        RegSAM samDesired,
        UInt32 Reserved);
        #endregion
        /// <summary>
        /// Registry creating volatile check.
        /// </summary>
        [Flags]
        public enum RegOption
        {
            NonVolatile = 0x0,
            Volatile = 0x1,
            CreateLink = 0x2,
            BackupRestore = 0x4,
            OpenLink = 0x8
        }
        /// <summary>
        /// Access mask the specifies the platform-specific view of the registry.
        /// </summary>
        [Flags]
        public enum RegSAM
        {
            QueryValue = 0x00000001,
            SetValue = 0x00000002,
            CreateSubKey = 0x00000004,
            EnumerateSubKeys = 0x00000008,
            Notify = 0x00000010,
            CreateLink = 0x00000020,
            WOW64_32Key = 0x00000200,
            WOW64_64Key = 0x00000100,
            WOW64_Res = 0x00000300,
            Read = 0x00020019,
            Write = 0x00020006,
            Execute = 0x00020019,
            AllAccess = 0x000f003f
        }
        /// <summary>
        /// Structure for security attributes.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public Int32 nLength;
            public IntPtr lpSecurityDescriptor;
            public Int32 bInheritHandle;
        }
        /// <summary>
        /// Flag returned by calling RegCreateKeyEx.
        /// </summary>
        public enum RegResult
        {
            CreatedNewKey = 0x00000001,
            OpenedExistingKey = 0x00000002
        }
        /// <summary>
        /// Class to create an object to handle the group policy operation.
        /// </summary>
        public class GroupPolicyObjectHandler
        {
            public const Int32 REG_NONE = 0;
            public const Int32 REG_SZ = 1;
            public const Int32 REG_EXPAND_SZ = 2;
            public const Int32 REG_BINARY = 3;
            public const Int32 REG_DWORD = 4;
            public const Int32 REG_DWORD_BIG_ENDIAN = 5;
            public const Int32 REG_MULTI_SZ = 7;
            public const Int32 REG_QWORD = 11;
            // Group Policy interface handler
            IGroupPolicyObject iGroupPolicyObject;
            // Group Policy object handler.
            GroupPolicyObject groupPolicyObject;
            #region constructor
            /// <summary>
            /// Constructor.
            /// </summary>
            /// <param name="remoteMachineName">Target machine name to operate group policy</param>
            /// <exception cref="System.Runtime.InteropServices.COMException">Throw when com execution throws exceptions</exception>
            public GroupPolicyObjectHandler(String remoteMachineName = null)
            {
                groupPolicyObject = new GroupPolicyObject();
                iGroupPolicyObject = (IGroupPolicyObject)groupPolicyObject;
                try
                {
                    if (String.IsNullOrEmpty(remoteMachineName))
                    {
                        iGroupPolicyObject.OpenLocalMachineGPO(GPO_OPEN_LOAD_REGISTRY);
                    }
                    else
                    {
                        iGroupPolicyObject.OpenRemoteMachineGPO(remoteMachineName, GPO_OPEN_LOAD_REGISTRY);
                    }
                }
                catch (COMException e)
                {
                    throw e;
                }
            }
            #endregion
            #region interface related methods
            /// <summary>
            /// Retrieves the display name for the GPO.
            /// </summary>
            /// <returns>Display name</returns>
            /// <exception cref="System.Runtime.InteropServices.COMException">Throw when com execution throws exceptions</exception>
            public String GetDisplayName()
            {
                StringBuilder pszName = new StringBuilder(Byte.MaxValue);
                try
                {
                    iGroupPolicyObject.GetDisplayName(pszName, Byte.MaxValue);
                }
                catch (COMException e)
                {
                    throw e;
                }
                return pszName.ToString();
            }
            /// <summary>
            /// Retrieves the computer name of the remote GPO.
            /// </summary>
            /// <returns>Machine name</returns>
            /// <exception cref="System.Runtime.InteropServices.COMException">Throw when com execution throws exceptions</exception>
            public String GetMachineName()
            {
                StringBuilder pszName = new StringBuilder(Byte.MaxValue);
                try
                {
                    iGroupPolicyObject.GetMachineName(pszName, Byte.MaxValue);
                }
                catch (COMException e)
                {
                    throw e;
                }
                return pszName.ToString();
            }
            /// <summary>
            /// Retrieves the options for the GPO.
            /// </summary>
            /// <returns>Options flag</returns>
            /// <exception cref="System.Runtime.InteropServices.COMException">Throw when com execution throws exceptions</exception>
            public Int32 GetOptions()
            {
                try
                {
                    return iGroupPolicyObject.GetOptions();
                }
                catch (COMException e)
                {
                    throw e;
                }
            }
            /// <summary>
            /// Retrieves the path to the GPO.
            /// </summary>
            /// <returns>The path to the GPO</returns>
            /// <exception cref="System.Runtime.InteropServices.COMException">Throw when com execution throws exceptions</exception>
            public String GetPath()
            {
                StringBuilder pszName = new StringBuilder(Byte.MaxValue);
                try
                {
                    iGroupPolicyObject.GetPath(pszName, Byte.MaxValue);
                }
                catch (COMException e)
                {
                    throw e;
                }
                return pszName.ToString();
            }
            /// <summary>
            /// Retrieves a handle to the root of the registry key for the machine section.
            /// </summary>
            /// <returns>A handle to the root of the registry key for the specified GPO computer section</returns>
            /// <exception cref="System.Runtime.InteropServices.COMException">Throw when com execution throws exceptions</exception>
            public UInt32 GetMachineRegistryKey()
            {
                UInt32 handle;
                try
                {
                    handle = iGroupPolicyObject.GetRegistryKey(GPO_OPTION_DISABLE_MACHINE);
                }
                catch (COMException e)
                {
                    throw e;
                }
                return handle;
            }
            /// <summary>
            /// Retrieves a handle to the root of the registry key for the user section.
            /// </summary>
            /// <returns>A handle to the root of the registry key for the specified GPO user section</returns>
            /// <exception cref="System.Runtime.InteropServices.COMException">Throw when com execution throws exceptions</exception>
            public UInt32 GetUserRegistryKey()
            {
                UInt32 handle;
                try
                {
                    handle = iGroupPolicyObject.GetRegistryKey(GPO_OPTION_DISABLE_USER);
                }
                catch (COMException e)
                {
                    throw e;
                }
                return handle;
            }
            /// <summary>
            /// Saves the specified registry policy settings to disk and updates the revision number of the GPO.
            /// </summary>
            /// <param name="isMachine">Specifies the registry policy settings to be saved. If this parameter is TRUE, the computer policy settings are saved. Otherwise, the user policy settings are saved.</param>
            /// <param name="isAdd">Specifies whether this is an add or delete operation. If this parameter is FALSE, the last policy setting for the specified extension pGuidExtension is removed. In all other cases, this parameter is TRUE.</param>
            /// <exception cref="System.Runtime.InteropServices.COMException">Throw when com execution throws exceptions</exception>
            public void Save(bool isMachine, bool isAdd)
            {
                try
                {
                    iGroupPolicyObject.Save(isMachine, isAdd, REGISTRY_EXTENSION_GUID, CLSID_GPESnapIn);
                }
                catch (COMException e)
                {
                    throw e;
                }
            }
            #endregion
            #region customized methods
            /// <summary>
            /// Set the group policy value.
            /// </summary>
            /// <param name="isMachine">Specifies the registry policy settings to be saved. If this parameter is TRUE, the computer policy settings are saved. Otherwise, the user policy settings are saved.</param>
            /// <param name="subKey">Group policy config full path</param>
            /// <param name="valueName">Group policy config key name</param>
            /// <param name="value">If value is null, it will envoke the delete method</param>
            /// <returns>Whether the config is successfully set</returns>
            public ResultCode SetGroupPolicy(bool isMachine, String subKey, String valueName, object value)
            {
                UInt32 gphKey = (isMachine) ? GetMachineRegistryKey() : GetUserRegistryKey();
                UInt32 gphSubKey;
                UIntPtr hKey;
                RegResult flag;
                if (null == value)
                {
                    // check the key’s existance
                    if (RegOpenKeyEx((UIntPtr)gphKey, subKey, 0, RegSAM.QueryValue, out hKey) == 0)
                    {
                        RegCloseKey((UInt32)hKey);
                        // delete the GPO
                        Int32 hr = RegDeleteKeyEx(
                        gphKey,
                        subKey,
                        RegSAM.Write,
                        0);
                        if (0 != hr)
                        {
                            RegCloseKey(gphKey);
                            return ResultCode.CreateOrOpenFailed;
                        }
                        Save(isMachine, false);
                    }
                    else
                    {
                        // not exist
                    }
                }
                else
                {
                    // set the GPO
                    Int32 hr = RegCreateKeyEx(
                    gphKey,
                    subKey,
                    0,
                    null,
                    RegOption.NonVolatile,
                    RegSAM.Write,
                    IntPtr.Zero,
                    out gphSubKey,
                    out flag);
                    if (0 != hr)
                    {
                        RegCloseKey(gphSubKey);
                        RegCloseKey(gphKey);
                        return ResultCode.CreateOrOpenFailed;
                    }
                    Int32 cbData = 4;
                    IntPtr keyValue = IntPtr.Zero;
                    if (value.GetType() == typeof(Int32))
                    {
                        keyValue = Marshal.AllocHGlobal(cbData);
                        Marshal.WriteInt32(keyValue, (Int32)value);
                        hr = RegSetValueEx(gphSubKey, valueName, 0, RegistryValueKind.DWord, keyValue, cbData);
                    }
                    else if (value.GetType() == typeof(String))
                    {
                        keyValue = Marshal.StringToBSTR(value.ToString());
                        cbData = System.Text.Encoding.Unicode.GetByteCount(value.ToString()) + 1;
                        hr = RegSetValueEx(gphSubKey, valueName, 0, RegistryValueKind.String, keyValue, cbData);
                    }
                    else
                    {
                        RegCloseKey(gphSubKey);
                        RegCloseKey(gphKey);
                        return ResultCode.SetFailed;
                    }
                    if (0 != hr)
                    {
                        RegCloseKey(gphSubKey);
                        RegCloseKey(gphKey);
                        return ResultCode.SetFailed;
                    }
                    try
                    {
                        Save(isMachine, true);
                    }
                    catch (COMException e)
                    {
                        RegCloseKey(gphSubKey);
                        RegCloseKey(gphKey);
                        return ResultCode.SaveFailed;
                    }
                    RegCloseKey(gphSubKey);
                    RegCloseKey(gphKey);
                }
                return ResultCode.Succeed;
            }
            /// <summary>
            /// Get the config of the group policy.
            /// </summary>
            /// <param name="isMachine">Specifies the registry policy settings to be saved. If this parameter is TRUE, get from the computer policy settings. Otherwise, get from the user policy settings.</param>
            /// <param name="subKey">Group policy config full path</param>
            /// <param name="valueName">Group policy config key name</param>
            /// <returns>The setting of the specified config</returns>
            public object GetGroupPolicy(bool isMachine, String subKey, String valueName)
            {
                UIntPtr gphKey = (UIntPtr)((isMachine) ? GetMachineRegistryKey() : GetUserRegistryKey());
                UIntPtr hKey;
                object keyValue = null;
                UInt32 size = 20;
                if (RegOpenKeyEx(gphKey, subKey, 0, RegSAM.Read, out hKey) == 0)
                {
                    UInt32 type;
                    byte[] data = new byte[size]; // to store retrieved the value’s data
                    if (RegQueryValueEx(hKey, valueName, 0, out type, data, ref size) != 0)
                    {
                        return null;
                    }
                    switch (type)
                    {
                        case REG_NONE:
                        case REG_BINARY:
                            keyValue = data;
                            break;
                        case REG_DWORD:
                            keyValue = (((data[0] | (data[1] << 8)) | (data[2] << 16)) | (data[3] << 24));
                            break;
                        case REG_DWORD_BIG_ENDIAN:
                            keyValue = (((data[3] | (data[2] << 8)) | (data[1] << 16)) | (data[0] << 24));
                            break;
                        case REG_QWORD:
                            {
                                UInt32 numLow = (UInt32)(((data[0] | (data[1] << 8)) | (data[2] << 16)) | (data[3] << 24));
                                UInt32 numHigh = (UInt32)(((data[4] | (data[5] << 8)) | (data[6] << 16)) | (data[7] << 24));
                                keyValue = (long)(((ulong)numHigh << 32) | (ulong)numLow);
                                break;
                            }
                        case REG_SZ:
                            keyValue = Encoding.Unicode.GetString(data, 0, (Int32)size);
                            break;
                        case REG_EXPAND_SZ:
                            keyValue = Environment.ExpandEnvironmentVariables(Encoding.Unicode.GetString(data, 0, (Int32)size));
                            break;
                        case REG_MULTI_SZ:
                            {
                                var strings = new List<String>();
                                String packed = Encoding.Unicode.GetString(data, 0, (Int32)size);
                                Int32 start = 0;
                                Int32 end = packed.IndexOf(' ', start);
                                while (end > start)
                                {
                                    strings.Add(packed.Substring(start, end - start));
                                    start = end + 1;
                                    end = packed.IndexOf(' ', start);
                                }
                                keyValue = strings.ToArray();
                                break;
                            }
                        default:
                            throw new NotSupportedException();
                    }
                    RegCloseKey((UInt32)hKey);
                }
                return keyValue;
            }
            /// <summary>
            /// Get the config of the group policy.
            /// </summary>
            /// <param name="isMachine">Specifies the registry policy settings to be saved. If this parameter is TRUE, get from the computer policy settings. Otherwise, get from the user policy settings.</param>
            /// <param name="subKey">Group policy config full path</param>
            /// <returns>The setting of the specified config</returns>
            public object EnumGroupPolicy(bool isMachine, String subKey)
            {
                UIntPtr gphKey = (UIntPtr)((isMachine) ? GetMachineRegistryKey() : GetUserRegistryKey());
                UIntPtr hKey;
                List<string> subKeys = new List<string>();
                uint size = 256;
                if (RegOpenKeyEx(gphKey, subKey, 0, RegSAM.Read, out hKey) == 0)
                {
                    UInt32 keyIndex = 0;
                    //byte[] data = new byte[size]; // to store retrieved the value’s data
                    StringBuilder keyName = new StringBuilder((int)size);
                    long lastWriteTime = 0;
                    do
                    {
                        if (RegEnumKeyEx(hKey, keyIndex++, keyName, ref size, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out lastWriteTime) != 0)
                        {
                            break;
                        }
                        subKeys.Add(keyName.ToString());
                    } while (true);
                    RegCloseKey((UInt32)hKey);
                }
                return subKeys;
            }
            internal object EnumGroupPolicyValue(bool isMachine, string configFullPath)
            {
                UIntPtr gphKey = (UIntPtr)((isMachine) ? GetMachineRegistryKey() : GetUserRegistryKey());
                UIntPtr hKey;
                List<string> subKeys = new List<string>();
                uint size = 256;
                if (RegOpenKeyEx(gphKey, configFullPath, 0, RegSAM.Read, out hKey) == 0)
                {
                    UInt32 valueIndex = 0;
                    UInt32 type;
                    //byte[] data = new byte[size]; // to store retrieved the value’s data
                    StringBuilder valueName = new StringBuilder((int)size);
                    UInt32 zero = 0;
                    do
                    {
                        if (RegEnumValue(hKey, valueIndex++, valueName, ref size, IntPtr.Zero, out type, null, ref zero) != 0)
                        {
                            break;
                        }
                        // get type name:
                        string typeString = "";
                        switch (type)
                        {
                            case REG_NONE: typeString = "REG_NONE"; break;
                            case REG_BINARY: typeString = "REG_BINARY"; break;
                            case REG_DWORD: typeString = "REG_DWORD"; break;
                            case REG_DWORD_BIG_ENDIAN: typeString = "REG_DWORD_BIG_ENDIAN"; break;
                            case REG_QWORD: typeString = "REG_QWORD"; break;
                            case REG_SZ: typeString = "REG_SZ"; break;
                            case REG_EXPAND_SZ: typeString = "REG_EXPAND_SZ"; break;
                            case REG_MULTI_SZ: typeString = "REG_MULTI_SZ"; break;
                            default:
                                throw new NotSupportedException();
                        }
                        subKeys.Add(string.Format("[{0}:{1}]", valueName, typeString));
                    } while (true);
                    RegCloseKey((UInt32)hKey);
                }
                return subKeys;
            }
            #endregion
        }
    }
    public class Helper
    {
        private static object _returnValueFromSet, _returnValueFromGet;
        /// <summary>
        /// Set policy config
        /// It will start a single thread to set group policy.
        /// </summary>
        /// <param name="isMachine">Whether is machine config</param>
        /// <param name="configFullPath">The full path configuration</param>
        /// <param name="configKey">The configureation key name</param>
        /// <param name="value">The value to set, boxed with proper type [ String, Int32 ]</param>
        /// <returns>Whether the config is successfully set</returns>
        [MethodImplAttribute(MethodImplOptions.Synchronized)]
        public static ResultCode SetGroupPolicy(bool isMachine, String configFullPath, String configKey, object value)
        {
            Thread worker = new Thread(SetGroupPolicy);
            worker.SetApartmentState(ApartmentState.STA);
            worker.Start(new object[] { isMachine, configFullPath, configKey, value });
            worker.Join();
            return (ResultCode)_returnValueFromSet;
        }
        /// <summary>
        /// Thread start for seting group policy.
        /// Called by public static ResultCode SetGroupPolicy(bool isMachine, WinRMGPConfigName configName, object value)
        /// </summary>
        /// <param name="values">
        /// values[0] - isMachine<br/>
        /// values[1] - configFullPath<br/>
        /// values[2] - configKey<br/>
        /// values[3] - value<br/>
        /// </param>
        private static void SetGroupPolicy(object values)
        {
            object[] valueList = (object[])values;
            bool isMachine = (bool)valueList[0];
            String configFullPath = (String)valueList[1];
            String configKey = (String)valueList[2];
            object value = valueList[3];
            WinAPIForGroupPolicy.GroupPolicyObjectHandler gpHandler = new WinAPIForGroupPolicy.GroupPolicyObjectHandler();
            _returnValueFromSet = gpHandler.SetGroupPolicy(isMachine, configFullPath, configKey, value);
        }
        /// <summary>
        /// Get policy config.
        /// It will start a single thread to get group policy
        /// </summary>
        /// <param name="isMachine">Whether is machine config</param>
        /// <param name="configFullPath">The full path configuration</param>
        /// <param name="configKey">The configureation key name</param>
        /// <returns>The group policy setting</returns>
        [MethodImplAttribute(MethodImplOptions.Synchronized)]
        public static object GetGroupPolicy(bool isMachine, String configFullPath, String configKey)
        {
            Thread worker = new Thread(GetGroupPolicy);
            worker.SetApartmentState(ApartmentState.STA);
            worker.Start(new object[] { isMachine, configFullPath, configKey });
            worker.Join();
            return _returnValueFromGet;
        }
        /// <summary>
        /// Thread start for geting group policy.
        /// Called by public static object GetGroupPolicy(bool isMachine, WinRMGPConfigName configName)
        /// </summary>
        /// <param name="values">
        /// values[0] - isMachine<br/>
        /// values[1] - configFullPath<br/>
        /// values[2] - configKey<br/>
        /// </param>
        public static void GetGroupPolicy(object values)
        {
            object[] valueList = (object[])values;
            bool isMachine = (bool)valueList[0];
            String configFullPath = (String)valueList[1];
            String configKey = (String)valueList[2];
            WinAPIForGroupPolicy.GroupPolicyObjectHandler gpHandler = new WinAPIForGroupPolicy.GroupPolicyObjectHandler();
            _returnValueFromGet = gpHandler.GetGroupPolicy(isMachine, configFullPath, configKey);
        }
        /// <summary>
        /// enumerate the sub keys of the given path
        /// </summary>
        /// <param name="isMachine">Whether is machine config</param>
        /// <param name="configFullPath">The full path configuration</param>
        /// <returns></returns>
        [MethodImplAttribute(MethodImplOptions.Synchronized)]
        public static List<string> EnumSubKeys(bool isMachine, String configFullPath)
        {
            Thread worker = new Thread(EnumSubKeys);
            worker.SetApartmentState(ApartmentState.STA);
            worker.Start(new object[] { isMachine, configFullPath });
            worker.Join();
            return (List<string>)_returnValueFromGet;
        }
        /// <summary>
        /// thread start for EnumSubKeys
        /// </summary>
        /// <param name="values">
        /// values[0] - isMachine<br/>
        /// values[1] - configFullPath<br/>
        /// </param>
        public static void EnumSubKeys(object values)
        {
            object[] valueList = (object[])values;
            bool isMachine = (bool)valueList[0];
            String configFullPath = (String)valueList[1];
            WinAPIForGroupPolicy.GroupPolicyObjectHandler gpHandler = new WinAPIForGroupPolicy.GroupPolicyObjectHandler();
            _returnValueFromGet = gpHandler.EnumGroupPolicy(isMachine, configFullPath);
        }
        /// <summary>
        /// enumerate the values of the given path
        /// </summary>
        /// <param name="isMachine">Whether is machine config</param>
        /// <param name="configFullPath">The full path configuration</param>
        /// <returns></returns>
        [MethodImplAttribute(MethodImplOptions.Synchronized)]
        public static List<string> EnumValues(bool isMachine, String configFullPath)
        {
            Thread worker = new Thread(EnumValues);
            worker.SetApartmentState(ApartmentState.STA);
            worker.Start(new object[] { isMachine, configFullPath });
            worker.Join();
            return (List<string>)_returnValueFromGet;
        }
        /// <summary>
        /// thread start for EnumValues
        /// </summary>
        /// <param name="values">
        /// values[0] - isMachine<br/>
        /// values[1] - configFullPath<br/>
        /// </param>
        public static void EnumValues(object values)
        {
            object[] valueList = (object[])values;
            bool isMachine = (bool)valueList[0];
            String configFullPath = (String)valueList[1];
            WinAPIForGroupPolicy.GroupPolicyObjectHandler gpHandler = new WinAPIForGroupPolicy.GroupPolicyObjectHandler();
            _returnValueFromGet = gpHandler.EnumGroupPolicyValue(isMachine, configFullPath);
        }
        /// <summary>
        /// enumerate the full tree
        /// </summary>
        /// <param name="isMachine">Whether is machine config</param>
        /// <param name="configFullPath">The full path configuration</param>
        /// <returns></returns>
        [MethodImplAttribute(MethodImplOptions.Synchronized)]
        public static StringBuilder EnumFullTree(bool isMachine, String configFullPath)
        {
            StringBuilder msg = new StringBuilder(configFullPath).AppendLine();
            System.Diagnostics.Trace.WriteLine(configFullPath);
            foreach (var value in EnumValues(isMachine, configFullPath))
            {
                msg.AppendLine(string.Format("\t{{{0}}}", value));
            }
            foreach (var subKey in EnumSubKeys(isMachine, configFullPath))
            {
                if (string.IsNullOrWhiteSpace(configFullPath))
                {
                    msg.Append(EnumFullTree(isMachine, subKey));
                }
                else
                {
                    msg.Append(EnumFullTree(isMachine, string.Format(@"{0}\{1}", configFullPath, subKey)));
                }
            }
            return msg;
        }
    }
}