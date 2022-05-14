using Microsoft.Win32.SafeHandles;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Reflection;
using Microsoft.Win32;

public class SignReader {

    // Hardcoding stuff is fun, you should try it
    public const string signOid = "1.3.6.1.4.1.38136.1337";
    public const string signSubject = "CN=Certone";

    public static int Main(string[] args) {
        // string codeBase = Assembly.GetExecutingAssembly().Location; // does not work for single file apps
        string codeBase = AppContext.BaseDirectory+System.AppDomain.CurrentDomain.FriendlyName;
        if (args.Length == 0) {
            System.Console.WriteLine($"Need a name of the signed executable to interrogate: \n {codeBase} <installer>");
            return 1;
        }
        try {
            // var thisPath = System.Reflection.Assembly.GetExecutingAssembly().Location;
            var signData = ReadSignFromFile(args[0], signSubject, signOid);
            var signText = Encoding.UTF8.GetString(signData);
            string[] signParts = signText.Split(' ');
            if (signParts.Length < 2) {
                System.Console.WriteLine($"Data can't be split: {signText}");
                return 3;
            }
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)){
                foreach (var part in signParts){
                    System.Console.WriteLine($"<{part}>");
                }
            } else {
		System.Console.WriteLine($"Success {signParts.Length}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Well this sucks: \n{ex.ToString()}");
            return 2;
        }
        return 0;
    }
    public static byte[] ReadSignFromFile(string path, string certSubjectName, string extensionOid) {
        try {
            var cert = GetOurCert(path, certSubjectName);
            var extensionData = cert.Extensions.Cast<X509Extension>().FirstOrDefault(s => s.Oid.Value == extensionOid);
            if (extensionData == null) {
                throw new Exception($"Certificate was found, but no extension with OID {extensionOid} was found");
            }
            return extensionData.RawData;
        } catch (Exception ex) {
            throw new Exception("An exception occurred while reading the cert data", ex);
        }
    }

    private static X509Certificate2 GetOurCert(string path, string subjectName) {
        var pkcs7data = GetPkcs7FromAuthenticodeExe(path);

        var cms = new SignedCms();
        cms.Decode(pkcs7data);

        foreach (var nested in cms.SignerInfos[0].UnsignedAttributes
            .Cast<CryptographicAttributeObject>()
            .Where(ca => ca.Oid.Value == NativeMethods.szOID_NESTED_SIGNATURE)
            .SelectMany(ca => ca.Values.Cast<AsnEncodedData>())
            .Where(ca => ca.Oid.Value == NativeMethods.szOID_NESTED_SIGNATURE)) {
            var cms2 = new SignedCms();
            cms2.Decode(nested.RawData);

            var subsigner = cms2.SignerInfos[0].Certificate;
            if (subsigner.Subject == subjectName) {
                return subsigner;
            }
        }

        throw new Exception("Cant find the right cert");
    }

    private static byte[] GetPkcs7FromAuthenticodeExe(string path) {
        uint dwEncoding, dwContentType, dwFormatType;
        NativeMethods.SafeCertStoreHandle hStore;
        NativeMethods.SafeCryptMsgHandle hMsg;
        if (!NativeMethods.CryptQueryObject(NativeMethods.CERT_QUERY_OBJECT.FILE, path, NativeMethods.CERT_QUERY_CONTENT.FLAG_PKCS7_SIGNED_EMBED,
            NativeMethods.CERT_QUERY_FORMAT.FLAG_BINARY, 0, out dwEncoding, out dwContentType, out dwFormatType,
            out hStore, out hMsg, IntPtr.Zero)) {
            throw new Win32Exception();
        }
        using (hMsg)
        using (hStore) {
            return ReadCryptMsgAttribute(hMsg, NativeMethods.CMSG_ENCODED_MESSAGE, 0);
        }
    }

    private static byte[] ReadCryptMsgAttribute(NativeMethods.SafeCryptMsgHandle hMsg, uint attribute, uint index) {
        int cbData = 0;
        // we cannot check the result because it seems to violate the docs
        NativeMethods.CryptMsgGetParam(hMsg, attribute, index, IntPtr.Zero, ref cbData);
        if (Marshal.GetLastWin32Error() != NativeMethods.ERROR_SUCCESS
            && Marshal.GetLastWin32Error() != NativeMethods.ERROR_MORE_DATA) {
            throw new Win32Exception();
        }

        var bResult = new byte[cbData];
        IntPtr pResult = Marshal.AllocHGlobal(cbData);
        try {
            if (!NativeMethods.CryptMsgGetParam(hMsg, attribute, index, pResult, ref cbData)) {
                throw new Win32Exception();
            }
            Marshal.Copy(pResult, bResult, 0, bResult.Length);
        } finally {
            Marshal.FreeHGlobal(pResult);
        }

        return bResult;
    }

    internal static class NativeMethods {
        internal const string Crypt32 = "crypt32.dll";

        public const int ERROR_SUCCESS = 0;
        public const int ERROR_MORE_DATA = 234;
        public const uint CMSG_ENCODED_MESSAGE = 29;
        public const string szOID_NESTED_SIGNATURE = "1.3.6.1.4.1.311.2.4.1";
        public enum CERT_QUERY_OBJECT : uint {
            FILE = 0x00000001
        }

        public enum CERT_QUERY_CONTENT : uint {
            FLAG_PKCS7_SIGNED_EMBED = 1 << 10
        }

        public enum CERT_QUERY_FORMAT : uint {
            FLAG_BINARY = 1 << 1
        }

        [DllImport(Crypt32, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CryptQueryObject(
            CERT_QUERY_OBJECT dwObjectType,
            [MarshalAs(UnmanagedType.LPWStr)] string pvObject,
            CERT_QUERY_CONTENT dwExpectedContentTypeFlags,
            CERT_QUERY_FORMAT dwExpectedFormatTypeFlags,
            [In] uint dwFlags,
            out uint pdwMsgAndCertEncodingType,
            out uint pdwContentType,
            out uint pdwFormatType,
            out SafeCertStoreHandle phCertStore,
            out SafeCryptMsgHandle phMsg,
            [In, Out] IntPtr ppvContext);

        [DllImport(Crypt32, SetLastError = true)]
        private static extern bool CertCloseStore(IntPtr hCertStore, uint dwFlags);

        [DllImport(Crypt32, SetLastError = true)]
        private static extern bool CryptMsgClose(IntPtr handle);

        [DllImport(Crypt32, CharSet = CharSet.Unicode, SetLastError = true)]
        public extern static bool CryptMsgGetParam(
            [In] SafeCryptMsgHandle hCryptMsg,
            [In] uint dwParamType,
            [In] uint dwIndex,
            [In, Out] IntPtr pvData,
            [In, Out] ref int pcbData);

        public sealed class SafeCertStoreHandle : SafeHandleZeroOrMinusOneIsInvalid {
            public SafeCertStoreHandle()
                : base(true) {
            }

            override protected bool ReleaseHandle() {
                return CertCloseStore(handle, 0);
            }
        }

        public sealed class SafeCryptMsgHandle : SafeHandleZeroOrMinusOneIsInvalid {
            private SafeCryptMsgHandle()
                : base(true) {
            }

            override protected bool ReleaseHandle() {
                return CryptMsgClose(handle);
            }
        }
    }

}
