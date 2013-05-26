/*
 * Created on 5 jan 2010
 */

package craterstudio.encryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Set;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import craterstudio.io.FileUtil;
import craterstudio.text.Text;
import craterstudio.util.SetUtil;

import java.security.Key;
import sun.misc.BASE64Encoder;

public class SSLUtil {

	static public void main(String[] args) throws Exception {
		if (args.length < 3) {
			throw new IllegalArgumentException("expected args: Keystore filename, Keystore password, alias, <key password: default same than keystore");
		}
		final String keystoreName = args[0];
		final String keystorePassword = args[1];
		final String alias = args[2];
		final String keyPassword = args[3];
		KeyStore ks = KeyStore.getInstance("jks");
		ks.load(new FileInputStream(keystoreName), keystorePassword.toCharArray());
		Key key = ks.getKey(alias, keyPassword.toCharArray());
		String b64 = new BASE64Encoder().encode(key.getEncoded());
		System.out.println("-----BEGIN PRIVATE KEY-----");
		System.out.println(b64);
		System.out.println("-----END PRIVATE KEY-----");
	}

	public static SSLContext createSSLContext(File keystoreFile, File storepassFile, File certpassFile, ProblematicCertificateHandler handler) throws SSLException, IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, KeyManagementException, NoSuchProviderException {
		char[] storepass = Text.utf8(FileUtil.readFile(storepassFile)).trim().toCharArray();
		char[] certpass = Text.utf8(FileUtil.readFile(certpassFile)).trim().toCharArray();

		KeyStore keystore = KeyStore.getInstance("JKS");
		keystore.load(new FileInputStream(keystoreFile), storepass);
		Arrays.fill(storepass, ' '); // overwrite password

		KeyManagerFactory keyManager = KeyManagerFactory.getInstance("SunX509");
		keyManager.init(keystore, certpass);
		Arrays.fill(certpass, ' '); // overwrite password

		X509TrustManager x509TrustManager = SSLUtil.findX509TrustManager(keystore);
		KeyManager[] keyManagers = keyManager.getKeyManagers();

		if (handler != null) {
			x509TrustManager = new HandlingX509TrustManager(x509TrustManager, handler);
		}

		SSLContext context = SSLContext.getInstance("TLS", "SunJSSE");
		context.init(keyManagers, new TrustManager[] { x509TrustManager }, new SecureRandom());
		return context;
	}

	public static SSLContext createSSLContext(KeytoolKey key, ProblematicCertificateHandler handler) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, NoSuchProviderException, KeyManagementException, CertificateException, IOException {
		char[] storePass = new char[key.store.password.length];
		for (int i = 0; i < storePass.length; i++)
			storePass[i] = (char) key.store.password[i];

		char[] keyPass = new char[key.password.length];
		for (int i = 0; i < keyPass.length; i++)
			keyPass[i] = (char) key.password[i];

		KeyStore keystore = KeyStore.getInstance("JKS");
		keystore.load(new FileInputStream(key.store.file), storePass);
		Arrays.fill(storePass, ' '); // overwrite password

		KeyManagerFactory keyManager = KeyManagerFactory.getInstance("SunX509");
		keyManager.init(keystore, keyPass);
		Arrays.fill(keyPass, ' '); // overwrite password

		X509TrustManager x509TrustManager = SSLUtil.findX509TrustManager(keystore);
		KeyManager[] keyManagers = keyManager.getKeyManagers();

		if (handler != null) {
			x509TrustManager = new HandlingX509TrustManager(x509TrustManager, handler);
		}

		SSLContext context = SSLContext.getInstance("TLS", "SunJSSE");
		context.init(keyManagers, new TrustManager[] { x509TrustManager }, new SecureRandom());
		return context;
	}

	private static X509TrustManager findX509TrustManager(KeyStore keystore) throws NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException {
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509", "SunJSSE");
		tmf.init(keystore);
		TrustManager tms[] = tmf.getTrustManagers();

		for (int i = 0; i < tms.length; i++)
			if (tms[i] instanceof X509TrustManager)
				return (X509TrustManager) tms[i];
		throw new IllegalStateException("X509TrustManager not found");
	}

	public static String[] removeOutdatedCiphers(SSLServerSocket socket) {
		System.out.println("SSL supported ciphers:");
		Set<String> set = SetUtil.create(socket.getEnabledCipherSuites());
		for (String item : set) {
			System.out.println("\t" + item);
		}

		String[] array = SetUtil.toArray(String.class, GOOD_CIPHERS == null ? set : SetUtil.and(GOOD_CIPHERS, set));
		System.out.println("SSL enabled ciphers:");
		for (String item : array) {
			System.out.println("\t" + item);
		}

		socket.setEnabledCipherSuites(array);
		return array;
	}

	public static String[] removeOutdatedCiphers(SSLSocket socket) {
		Set<String> set = SetUtil.create(socket.getEnabledCipherSuites());
		String[] array = SetUtil.toArray(String.class, GOOD_CIPHERS == null ? set : SetUtil.and(GOOD_CIPHERS, set));
		socket.setEnabledCipherSuites(array);
		return array;
	}

	public static Set<String> GOOD_CIPHERS = null;

	static class HandlingX509TrustManager implements X509TrustManager {
		private final X509TrustManager backing;
		private final ProblematicCertificateHandler handler;

		public HandlingX509TrustManager(X509TrustManager backing, ProblematicCertificateHandler handler) {
			this.backing = backing;
			this.handler = handler;
		}

		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			try {
				this.backing.checkClientTrusted(chain, authType);
			} catch (CertificateException exc) {
				if (!handler.acceptProblematicClient(chain, authType, exc)) {
					throw exc;
				}
			}
		}

		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			try {
				this.backing.checkServerTrusted(chain, authType);
			} catch (CertificateException exc) {
				if (!handler.acceptProblematicServer(chain, authType, exc)) {
					throw exc;
				}
			}
		}

		public X509Certificate[] getAcceptedIssuers() {
			return this.backing.getAcceptedIssuers();
		}
	}
}
