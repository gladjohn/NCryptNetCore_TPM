using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

class Program
{
    [DllImport("Ncrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, int dwFlags);

    [DllImport("Ncrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int NCryptCreatePersistedKey(IntPtr hProvider, out IntPtr phKey, string pszAlgId,
        string pszKeyName, int dwLegacyKeySpec, int dwFlags);

    [DllImport("Ncrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int NCryptSetProperty(IntPtr hObject, string pszProperty, [MarshalAs(UnmanagedType.LPArray)] byte[] pbInput, int cbInput, int dwFlags);

    [DllImport("Ncrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int NCryptSetProperty(IntPtr hObject, string pszProperty, string pbInput, int cbInput, int dwFlags);

    [DllImport("Ncrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int NCryptSetProperty(IntPtr hObject, string pszProperty, IntPtr pbInput, int cbInput, int dwFlags);


    [DllImport("Ncrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int NCryptFinalizeKey(IntPtr hKey, int dwFlags);

    [DllImport("Ncrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int NCryptEncrypt(IntPtr hKey, [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbInput, int cbInput,
        [In] IntPtr pvPadding, [Out, MarshalAs(UnmanagedType.LPArray)] byte[] pbOutput, int cbOutput,
        [Out] out int pcbResult, int dwFlags);

    [DllImport("Ncrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int NCryptExportKey(IntPtr hKey, IntPtr hExportKey, string pszBlobType, IntPtr pParameterList,
        [Out, MarshalAs(UnmanagedType.LPArray)] byte[] pbOutput, int cbOutput, [Out] out int pcbResult, int dwFlags);

    [DllImport("Ncrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int NCryptDeleteKey(IntPtr hKey, int flags);

    [DllImport("Ncrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int NCryptFreeObject(IntPtr hObject);

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CryptDecrypt(IntPtr hKey, IntPtr hHash, bool Final, int dwFlags,
        [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] pbData, [In, Out] int pdwDataLen);


    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CryptImportKey(IntPtr hProv, [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbData, int dwDataLen, IntPtr hPubKey, int dwFlags, [Out] out IntPtr phKey);

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CryptDestroyKey(IntPtr hKey);

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CryptAcquireContextW(out IntPtr phProv, string szContainer, string szProvider, int dwProvType, int dwFlags);

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CryptReleaseContext(IntPtr hProv, int dwFlags);

    [DllImport("tbs.dll")]
    static extern int Tbsi_Context_Create(uint dwFlags, out IntPtr phContext);

    [DllImport("tbs.dll")]
    static extern int Tbsip_Context_Close(IntPtr hContext);

    const uint TBS_CONTEXT_PARAMS_DEFAULT = 0;
    const uint NCRYPT_MACHINE_KEY_FLAG = 0x20;

    public const string MS_KEY_STORAGE_PROVIDER = "Microsoft Software Key Storage Provider";
    public const string MS_SMART_CARD_KEY_STORAGE_PROVIDER = "Microsoft Smart Card Key Storage Provider";
    public const string MS_PLATFORM_KEY_STORAGE_PROVIDER = "Microsoft Platform Crypto Provider";
    public const string MS_NGC_KEY_STORAGE_PROVIDER = "Microsoft Passport Key Storage Provider";

    public const string NCRYPT_RSA_ALGORITHM = "RSA";
    public const string NCRYPT_AES_ALGORITHM = "AES";

    public const int NCRYPT_OVERWRITE_KEY_FLAG = 0x00000080;

    public const int NCRYPT_ALLOW_EXPORT_FLAG = 0x00000001;
    public const int NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG = 0x00000002;
    public const int NCRYPT_ALLOW_ARCHIVING_FLAG = 0x00000004;
    public const int NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG = 0x00000008;

    public const string NCRYPT_UI_POLICY_PROPERTY = "UI Policy";
    public const string NCRYPT_EXPORT_POLICY_PROPERTY = "Export Policy";

    public const int NCRYPT_PERSIST_FLAG = unchecked((int)0x80000000);
    public const int NCRYPT_PERSIST_ONLY_FLAG = 0x40000000;

    public const int NCRYPT_NO_PADDING_FLAG = 0x00000001;  // NCryptEncrypt/Decrypt
    public const int NCRYPT_PAD_PKCS1_FLAG = 0x00000002;  // NCryptEncrypt/Decrypt NCryptSignHash/VerifySignature
    public const int NCRYPT_PAD_OAEP_FLAG = 0x00000004;  // BCryptEncrypt/Decrypt
    public const int NCRYPT_PAD_PSS_FLAG = 0x00000008;  // BCryptSignHash/VerifySignature
    public const int NCRYPT_PAD_CIPHER_FLAG = 0x00000010;  // NCryptEncrypt/Decrypt
    public const int NCRYPT_ATTESTATION_FLAG = 0x00000020; // NCryptDecrypt for key attestation
    public const int NCRYPT_SEALING_FLAG = 0x00000100; // NCryptEncrypt/Decrypt for sealing

    public const string BCRYPT_RSAPUBLIC_BLOB = "RSAPUBLICBLOB";
    public const string BCRYPT_RSAPRIVATE_BLOB = "RSAPRIVATEBLOB";
    public const string LEGACY_RSAPUBLIC_BLOB = "CAPIPUBLICBLOB";
    public const string LEGACY_RSAPRIVATE_BLOB = "CAPIPRIVATEBLOB";

    private readonly byte[] Data = { 0x04, 0x87, 0xec, 0x66, 0xa8, 0xbf, 0x17, 0xa6, 0xe3, 0x62, 0x6f, 0x1a, 0x55, 0xe2, 0xaf, 0x5e, 0xbc, 0x54, 0xa4, 0xdc, 0x68, 0x19, 0x3e, 0x94 };

    static void Main()
    {
        IntPtr hProvider = IntPtr.Zero;
        IntPtr hKey = IntPtr.Zero;

        try
        {
            // Step 1: Acquire a TPM handle
            IntPtr tpmHandle;
            int result = Tbsi_Context_Create(TBS_CONTEXT_PARAMS_DEFAULT, out tpmHandle);

            if (result != 0)
            {
                throw new CryptographicException("Failed to acquire TPM handle: " + result);
            }

            // Step 2: Create a storage key in the TPM
            IntPtr keyHandle;
            result = NCryptCreatePersistedKey(tpmHandle, out keyHandle, "RSA", "MyKey", 0, (int)CngKeyCreationOptions.MachineKey);
            if (result != 0)
            {
                throw new CryptographicException("Failed to create persistent key: " + result);
            }

            // Step 3: Use the key to perform a cryptographic operation
            byte[] plaintext = Encoding.UTF8.GetBytes("Hello, TPM!");
            byte[] ciphertext = new byte[2048 / 8];
            int bytesNeeded;
            result = NCryptEncrypt(keyHandle, plaintext, plaintext.Length, IntPtr.Zero, ciphertext, ciphertext.Length, out bytesNeeded, 0);
            if (result != 0)
            {
                throw new CryptographicException("Failed to encrypt data: " + result);
            }

            Console.WriteLine("Encrypted data: " + Convert.ToBase64String(ciphertext));

            // Step 4: Close the key
            NCryptFreeObject(keyHandle);

            // Step 5: Close the TPM handle
            Tbsip_Context_Close(tpmHandle);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.ToString());
        }

        // Wait for input before closing the console
        Console.ReadLine();
    }

}
