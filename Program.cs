using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net.Mail;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SAMLCertChecker
{
    class Program
    {
        public static string uatLocation = ConfigurationManager.AppSettings["uatfilelocation"];
        public static string prodLocation = ConfigurationManager.AppSettings["prodfilelocation"];

        static void Main(string[] args)
        {
            var allowedExtensions = new List<string> { "cer", "crt" };
            var expiredCerts = new List<string>();
            var certsAboutToExpire = new List<string>();

            var dateNow = DateTime.Now;
            var certFiles = Directory.EnumerateFiles(prodLocation, "*.*", SearchOption.TopDirectoryOnly).Where(i => allowedExtensions.Contains(Path.GetExtension(i).TrimStart('.').ToLowerInvariant()));
            if (certFiles.Count() > 0)
            {
                foreach (var cert in certFiles)
                {
                    try
                    {
                        var certText = File.ReadAllText(cert);
                        if (!string.IsNullOrEmpty(certText))
                        {
                            certText = certText.Replace("-----BEGIN CERTIFICATE-----", "").Replace("-----END CERTIFICATE-----", "");
                            certText = Regex.Replace(certText, @"\s+", "");
                            var certBytes = Encoding.ASCII.GetBytes(certText);
                            var actualCert = new X509Certificate(certBytes);

                            var certExpirationDate = Convert.ToDateTime(actualCert.GetExpirationDateString());
                            if (certExpirationDate < dateNow)
                            {
                                expiredCerts.Add(Path.GetFileName(cert));
                            }
                            else if ((certExpirationDate - dateNow).TotalDays < 30)
                            {
                                certsAboutToExpire.Add(Path.GetFileName(cert) + " (Exp: " + certExpirationDate.Date.Date + ")");
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        continue;
                    }
                }
            }

            var html = string.Empty;
            if (certsAboutToExpire.Count() > 0)
            {
                html += "Run Date: " + dateNow + "\r\n\r\n";
                html += "Following SAML SSO certificates are about to expire. Please check. \r\n\r\n";
                certsAboutToExpire.ForEach(i =>
                {
                    html += "- " + i.Trim() + "\r\n";
                });
            }

            //if (expiredCerts.Count() > 0)
            //{
            //    html += "\r\n\r\n";
            //    html = "Following certificates have expired already. Please check. \r\n";
            //    expiredCerts.ForEach(i =>
            //    {
            //        html += "- " + i.Trim() + "\r\n";
            //    });
            //}
            if(!string.IsNullOrEmpty(html))
                SendEmail(html);
        }

        public static void SendEmail(string emailBody)
        {
            var mailClient = new SmtpClient("x2.eduneering.com", 25);
            var internalEmail = new MailMessage();
            //internalEmail.IsBodyHtml = true;
            internalEmail.Sender = new MailAddress("SAMLCertChecker@UL.com");
            internalEmail.From = new MailAddress("SAMLCertChecker@UL.com");
            internalEmail.To.Add("parth.shah@ul.com");
            internalEmail.Subject = "SAML Certificate Check";
            internalEmail.Body = emailBody;
            try
            {
                mailClient.Send(internalEmail);
            }
            catch (Exception)
            {
                internalEmail.Dispose();
            }
            finally
            {
                internalEmail.Dispose();
            }
        }
    }
}
