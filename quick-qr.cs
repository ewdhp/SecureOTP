using System;
using SecureOTP;

public class QRGenerator 
{
    public static void Main(string[] args)
    {
        var manager = new TotpManager("demo-key");
        var result = manager.CreateAccount("demo@test.com", "TestApp");
        Console.WriteLine("QR_CODE_URI:");
        Console.WriteLine(result.QrCodeUri);
        Console.WriteLine();
        Console.WriteLine("CURRENT_CODE:");
        var code = manager.GenerateCode("demo@test.com");
        Console.WriteLine(code.Code);
    }
}