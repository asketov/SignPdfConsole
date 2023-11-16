using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using com.itextpdf.text.pdf.security;
using iTextSharp.text;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using iTextSharp.text.error_messages;
using Org.BouncyCastle.Crypto.Tls;
using static iTextSharp.text.pdf.codec.TiffWriter;
using System.Globalization;
using System.Reflection.PortableExecutable;
using  Org.BouncyCastle.X509;
using Org.BouncyCastle.Utilities.Encoders;

string beginPdf = "C:\\Users\\asket\\Downloads\\Протокол-13273-23.noSign.pdf", endPdf = "C:\\Users\\asket\\Downloads\\Протокол-13273-23.temp.pdf",
    sign =  Regex.Replace(File.ReadAllText("C:\\Users\\asket\\Downloads\\signKey.txt"), @"[\r\n\t ]+", "");
byte[] tempBytes;

//var m = GetBytesToSign(beginPdf, "C:\\Users\\asket\\Downloads\\1234.pdf", "signField");

//EmbedSignature("C:\\Users\\asket\\Downloads\\1234.pdf", beginPdf, "signField", Encoding.UTF8.GetBytes(sign));


string base64Crt = Regex.Replace(CryproProSignPdf.Consts.certBase64, @"[\r\n\t ]+", "");
X509CertificateParser parser = new X509CertificateParser();
X509Certificate cert;
using (MemoryStream stream = new MemoryStream(Base64.Decode(base64Crt)))
{
    cert = parser.ReadCertificate(stream);
}
//var hash = EmptySignature(beginPdf, "C:\\Users\\asket\\source\\repos\\ConsoleApp1\\ConsoleApp1\\pdfs\\Протокол-13273-23.temp.pdf", "sign1", new X509Certificate[] { cert });
//var res = Hex.ToHexString(hash);
//Console.WriteLine(res);
CreateSignature("C:\\Users\\asket\\source\\repos\\ConsoleApp1\\ConsoleApp1\\pdfs\\Протокол-13273-23.temp.pdf", "C:\\Users\\asket\\source\\repos\\ConsoleApp1\\ConsoleApp1\\pdfs\\result.pdf", "sign1", Base64.Decode(Regex.Replace(CryproProSignPdf.Consts.signMessage, @"[\r\n\t ]+", "")));





static byte[] EmptySignature(string src, string dest, string fieldName, X509Certificate[] chain)
{
    using (PdfReader reader = new PdfReader(src))
    using (FileStream os = new FileStream(dest, FileMode.Create))
    {
        using (PdfStamper stamper = PdfStamper.CreateSignature(reader, os, '\0'))
        {
            PdfSignatureAppearance appearance = stamper.SignatureAppearance;
            int countPages = reader.NumberOfPages, countSignatures = CountSignatures(reader);
            Rectangle lastPage = reader.GetPageSize(countPages);
            appearance.SetVisibleSignature(new Rectangle(lastPage.GetRight(100 + 50 * countSignatures),
                lastPage.GetBottom(100), lastPage.GetRight(50 + 50 * countSignatures),
                lastPage.GetBottom(50)), countPages, "signature" + countSignatures);
            appearance.Location = "RadarIT";
            appearance.Reason = "Подтверждение";
            appearance.Certificate = chain[0];
            ExternalBlankSignatureContainer external = new ExternalBlankSignatureContainer(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
            MakeSignature.SignExternalContainer(appearance, external, 8192);

            //PdfPKCS7 sgn = new PdfPKCS7(null, chain, "GOST3411", false);
            var data = appearance.GetRangeStream();
            byte[] hash = DigestAlgorithms.Digest(data, "GOST3411-2012-256");
            return hash;
        }
    }
}

static void CreateSignature(string src, string dest, string fieldName, byte[] signature)
{
    using (PdfReader reader = new PdfReader(src))
    using (FileStream os = new FileStream(dest, FileMode.OpenOrCreate))
    {
        IExternalSignatureContainer external = new MyExternalSignatureContainer(signature);
        MakeSignature.SignDeferred(reader, fieldName, os, external);
    }
}

static int CountSignatures(PdfReader reader)
{
    int signatureCount = 0;
    AcroFields af = reader.AcroFields;
    foreach (var name in af.GetSignatureNames())
    {
        PdfPKCS7 pkcs7 = af.VerifySignature(name);
        if (!pkcs7.IsTsp)
        {
            signatureCount++;
        }
    }
    return signatureCount;
}


class MyExternalSignatureContainer : IExternalSignatureContainer
{
    private readonly byte[] signedBytes;

    public MyExternalSignatureContainer(byte[] signedBytes)
    {
        this.signedBytes = signedBytes;
    }

    public byte[] Sign(Stream data)
    {
        return signedBytes;
    }

    public void ModifySigningDictionary(PdfDictionary signDic)
    {
    }
}







