/*
 * Created on 7 jan 2010
 */

package craterstudio.encryption;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public interface ProblematicCertificateHandler
{
   public boolean acceptProblematicServer(X509Certificate[] chain, String authType, CertificateException exc);

   public boolean acceptProblematicClient(X509Certificate[] chain, String authType, CertificateException exc);
}