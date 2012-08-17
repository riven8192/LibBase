/*
 * Created on Jun 3, 2012
 */

package craterstudio.encryption;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Properties;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import craterstudio.func.Callback;
import craterstudio.io.FileUtil;
import craterstudio.io.Streams;
import craterstudio.io.TcpServer;
import craterstudio.text.Text;
import craterstudio.text.TextDateTime;

public class SSLTunnel {
   public static void main(String[] args) throws Exception {
      String confpath = "./ssltunnel.conf";
      Properties props = new Properties();
      props.load(new StringReader(Text.utf8(FileUtil.readFile(new File(confpath)))));
      
      final String listenHost = props.getProperty("listen.host");
      final String targetHost = props.getProperty("target.host");
      final int listenPort = Integer.parseInt(props.getProperty("listen.port"));
      final int targetPort = Integer.parseInt(props.getProperty("target.port"));
      
      String alias = props.getProperty("ssl.alias");
      String storePasswd = props.getProperty("ssl.store.pass");
      String aliasPasswd = props.getProperty("ssl.alias.pass");
      
      String keystorePath = props.getProperty("ssl.store.path");
      KeytoolStore store = new KeytoolStore(new File(keystorePath), Text.ascii(storePasswd));
      KeytoolKey key = new KeytoolKey(store, alias, Text.ascii(aliasPasswd));
      
      int backlog = 50;
      final InetAddress listenAddr = InetAddress.getByName(listenHost);
      SSLServerSocket listen = createSSLServerSocket(key, listenPort, backlog, listenAddr);
      
      final int threadCount = Integer.parseInt(props.getProperty("thread.count"));
      final int threadIdle = Integer.parseInt(props.getProperty("thread.idle"));
      final int threadStack = Integer.parseInt(props.getProperty("thread.stack"));
      final int tcpTimeout = Integer.parseInt(props.getProperty("tcp.timeout"));
      
      final ExecutorService pool = TcpServer.pool(threadCount, threadIdle, threadStack);
      
      TcpServer.listen(listen, new Callback<Socket>() {
         @Override
         public void callback(Socket item) {
            final SSLSocket client = (SSLSocket) item;
            String clientString = client.getInetAddress().toString();
            
            Socket target = null;
            Future<Long> received = null;
            long sent = 0L;
            try {
               client.startHandshake();
               
               InetAddress targetAddr = InetAddress.getByName(targetHost);
               target = new Socket(targetAddr, targetPort);
               
               System.out.println(TextDateTime.now() + " " + clientString + " -> " + targetHost);
               
               client.setSoTimeout(tcpTimeout);
               target.setSoTimeout(tcpTimeout);
               
               final Socket target0 = target;
               
               received = pool.submit(new Callable<Long>() {
                  @Override
                  public Long call() {
                     try {
                        long got = copy(client.getInputStream(), target0.getOutputStream());
                        return Long.valueOf(got);
                     }
                     catch (IOException exc) {
                        return Long.valueOf(0L);
                     }
                     finally {
                        Streams.safeClose(client);
                        Streams.safeClose(target0);
                     }
                  }
               });
               
               sent = copy(target.getInputStream(), client.getOutputStream());
               
            }
            catch (Exception exc) {
               // exc.printStackTrace();
            }
            finally {
               Streams.safeClose(client);
               Streams.safeClose(target);
            }
            
            try {
               System.out.println(TextDateTime.now() + " " + clientString + ", R=" + received.get().longValue() / 1024 + "K, S=" + sent / 1024 + "K");
            }
            catch (Exception exc) {
               //
            }
         }
      }, pool);
   }
   
   static long copy(InputStream src, OutputStream dst) {
      long copied = 0L;
      try {
         byte[] buffer = new byte[8 * 1024];
         for (int got = 0; (got = src.read(buffer)) != -1; copied += got) {
            dst.write(buffer, 0, got);
         }
         dst.flush();
      }
      catch (IOException exc) {
         // ignore
      }
      return copied;
   }
   
   public static SSLServerSocket createSSLServerSocket(KeytoolKey key, int port, int backlog, InetAddress addr) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, KeyManagementException, NoSuchProviderException {
      SSLContext context = SSLUtil.createSSLContext(key, null);
      SSLServerSocketFactory ssf = context.getServerSocketFactory();
      SSLServerSocket server = (SSLServerSocket) ssf.createServerSocket(port, backlog, addr);
      
      SSLUtil.removeOutdatedCiphers(server);
      
      return server;
   }
}