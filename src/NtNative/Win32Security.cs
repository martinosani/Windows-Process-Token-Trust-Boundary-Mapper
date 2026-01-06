using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace WTBM.NtNative
{
    internal static class Win32Security
    {
        internal sealed record SecurityDescriptorInfo(
                string Sddl,
                string OwnerSid,
                string OwnerName
            );

        // Common file access bits (WinNT / WinBase)
        public const uint READ_CONTROL = 0x00020000;
        public const uint SYNCHRONIZE = 0x00100000;

        public const uint FILE_READ_DATA = 0x0001;
        public const uint FILE_READ_ATTRIBUTES = 0x0080;
        public const uint FILE_READ_EA = 0x0008;

        public static bool HasAny(uint granted, uint mask) => (granted & mask) != 0;

        public static SecurityDescriptorInfo GetSecurityDescriptorByHandle(IntPtr handle)
        {
            // We intentionally request OWNER + GROUP + DACL. SACL requires SeSecurityPrivilege.
            const SecurityInformation si =
                SecurityInformation.OWNER_SECURITY_INFORMATION |
                SecurityInformation.GROUP_SECURITY_INFORMATION |
                SecurityInformation.DACL_SECURITY_INFORMATION;

            uint err = GetSecurityInfo(
                handle,
                SE_OBJECT_TYPE.SE_FILE_OBJECT,
                si,
                out IntPtr pOwnerSid,
                out IntPtr _,
                out IntPtr _,
                out IntPtr _,
                out IntPtr pSecurityDescriptor);

            if (err != 0)
                throw new Win32Exception((int)err, "GetSecurityInfo(handle) failed.");

            try
            {
                if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
                        pSecurityDescriptor,
                        SDDL_REVISION_1,
                        si,
                        out IntPtr pSddl,
                        out uint _))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "ConvertSecurityDescriptorToStringSecurityDescriptor failed.");
                }

                string sddl;
                try
                {
                    sddl = Marshal.PtrToStringUni(pSddl) ?? string.Empty;
                }
                finally
                {
                    LocalFree(pSddl);
                }

                string ownerSid = pOwnerSid != IntPtr.Zero
                    ? new SecurityIdentifier(pOwnerSid).Value
                    : string.Empty;

                string ownerName = "<unknown>";
                if (pOwnerSid != IntPtr.Zero)
                {
                    try
                    {
                        var sid = new SecurityIdentifier(pOwnerSid);
                        ownerName = sid.Translate(typeof(NTAccount)).Value;
                    }
                    catch
                    {
                        ownerName = ownerSid;
                    }
                }

                return new SecurityDescriptorInfo(sddl, ownerSid, ownerName);
            }
            finally
            {
                if (pSecurityDescriptor != IntPtr.Zero)
                    LocalFree(pSecurityDescriptor);
            }
        }

        /// <summary>
        /// Reads the security descriptor for a named pipe path like \\.\pipe\X and returns:
        /// - SDDL for the security descriptor (Owner/Group/DACL by default)
        /// - Owner SID string (S-1-...)
        /// - Owner account name (DOMAIN\User), best-effort
        /// </summary>
        public static SecurityDescriptorInfo GetSecurityDescriptor(string win32Path)
        {
            if (string.IsNullOrWhiteSpace(win32Path))
                throw new ArgumentException("Path must be non-empty.", nameof(win32Path));

            // We intentionally request OWNER + GROUP + DACL. SACL requires SeSecurityPrivilege.
            const SecurityInformation si =
                SecurityInformation.OWNER_SECURITY_INFORMATION |
                SecurityInformation.GROUP_SECURITY_INFORMATION |
                SecurityInformation.DACL_SECURITY_INFORMATION;

            IntPtr pOwnerSid = IntPtr.Zero;
            IntPtr pGroupSid = IntPtr.Zero;
            IntPtr pDacl = IntPtr.Zero;
            IntPtr pSacl = IntPtr.Zero;
            IntPtr pSecurityDescriptor = IntPtr.Zero;

            try
            {
                uint err = GetNamedSecurityInfoW(
                    win32Path,
                    SE_OBJECT_TYPE.SE_FILE_OBJECT, // named pipes are file objects
                    si,
                    out pOwnerSid,
                    out pGroupSid,
                    out pDacl,
                    out pSacl,
                    out pSecurityDescriptor);

                if (err != 0)
                    throw new Win32Exception((int)err, $"GetNamedSecurityInfo failed for '{win32Path}'.");

                // Convert returned SD (self-relative) to SDDL string.
                if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
                        pSecurityDescriptor,
                        SDDL_REVISION_1,
                        si,
                        out IntPtr pSddl,
                        out uint _))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "ConvertSecurityDescriptorToStringSecurityDescriptor failed.");
                }

                string sddl;
                try
                {
                    sddl = Marshal.PtrToStringUni(pSddl) ?? string.Empty;
                }
                finally
                {
                    LocalFree(pSddl);
                }

                // Owner SID string
                string ownerSid = pOwnerSid != IntPtr.Zero
                    ? new SecurityIdentifier(pOwnerSid).Value
                    : string.Empty;

                // Owner name best-effort
                string ownerName = ResolveAccountNameBestEffort(pOwnerSid);

                return new SecurityDescriptorInfo(
                    Sddl: sddl,
                    OwnerSid: ownerSid,
                    OwnerName: ownerName
                );
            }
            finally
            {
                // Free SD returned by GetNamedSecurityInfo (LocalAlloc).
                if (pSecurityDescriptor != IntPtr.Zero)
                    LocalFree(pSecurityDescriptor);
            }
        }

        private static string ResolveAccountNameBestEffort(IntPtr pSid)
        {
            if (pSid == IntPtr.Zero)
                return "<unknown>";

            try
            {
                var sid = new SecurityIdentifier(pSid);
                try
                {
                    // This will use LSA/LookupAccountSid behind the scenes.
                    var ntAccount = (NTAccount)sid.Translate(typeof(NTAccount));
                    return ntAccount.Value; // DOMAIN\User
                }
                catch
                {
                    // Not resolvable -> return SID string
                    return sid.Value;
                }
            }
            catch
            {
                return "<unresolved>";
            }
        }

        // --- P/Invoke ------------------------------------------------------------

        private const uint SDDL_REVISION_1 = 1;

        [Flags]
        private enum SecurityInformation : uint
        {
            OWNER_SECURITY_INFORMATION = 0x00000001,
            GROUP_SECURITY_INFORMATION = 0x00000002,
            DACL_SECURITY_INFORMATION = 0x00000004,
            SACL_SECURITY_INFORMATION = 0x00000008,
            LABEL_SECURITY_INFORMATION = 0x00000010
        }

        private enum SE_OBJECT_TYPE
        {
            SE_UNKNOWN_OBJECT_TYPE = 0,
            SE_FILE_OBJECT = 1
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint GetSecurityInfo(
            IntPtr handle,
            SE_OBJECT_TYPE ObjectType,
            SecurityInformation SecurityInfo,
            out IntPtr ppsidOwner,
            out IntPtr ppsidGroup,
            out IntPtr ppDacl,
            out IntPtr ppSacl,
            out IntPtr ppSecurityDescriptor);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetNamedSecurityInfoW(
            string pObjectName,
            SE_OBJECT_TYPE ObjectType,
            SecurityInformation SecurityInfo,
            out IntPtr ppsidOwner,
            out IntPtr ppsidGroup,
            out IntPtr ppDacl,
            out IntPtr ppSacl,
            out IntPtr ppSecurityDescriptor
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(
            IntPtr SecurityDescriptor,
            uint RequestedStringSDRevision,
            SecurityInformation SecurityInformation,
            out IntPtr StringSecurityDescriptor,
            out uint StringSecurityDescriptorLen
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);
    }
}
