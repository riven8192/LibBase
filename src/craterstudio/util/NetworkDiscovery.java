package craterstudio.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;

public class NetworkDiscovery
{
   public static class BroadcastProperties
   {
      public final String      serviceName;
      public InetSocketAddress bindAddress;
      public InetSocketAddress toAddress;
      public InetSocketAddress aboutService;
      public long              interval;
      public int               times;

      public BroadcastProperties(String serviceName)
      {
         this.serviceName = serviceName;
      }
   }

   public static class DiscoveryProperties
   {
      public final String      serviceName;
      public InetSocketAddress bind;
      public long              maxTries;
      public int               socketTimeout;

      public DiscoveryProperties(String serviceName)
      {
         this.serviceName = serviceName;
      }
   }

   public static final void broadcastService(BroadcastProperties props) throws IOException
   {
      DatagramSocket socket = new DatagramSocket(props.bindAddress);

      byte[] packetData;
      {
         ByteArrayOutputStream baos = new ByteArrayOutputStream();
         DataOutputStream dos = new DataOutputStream(baos);
         dos.writeUTF(props.serviceName);
         dos.writeUTF(props.aboutService.getHostName());
         dos.writeInt(props.aboutService.getPort());
         dos.flush();
         packetData = baos.toByteArray();
      }

      try
      {
         for (int i = 0; (i < props.times) || (props.times == -1); i++)
         {
            socket.send(new DatagramPacket(packetData, 0, packetData.length, props.toAddress));

            try
            {
               Thread.sleep(props.interval);
            }
            catch (InterruptedException exc)
            {
               exc.printStackTrace();
            }
         }
      }
      catch (Exception exc)
      {
         exc.printStackTrace();
      }
   }

   /**
    * Listens for UDP packets at the specified <code>port</code>.<br>
    * Only returns when the received packet has the specified <code>name</code>.<br>
    * This way multiple broadcasting sockets per UDP port are supported
    */

   public static final InetSocketAddress discoverService(DiscoveryProperties discoveryProperties)
   {
      try
      {
         int packetLength = 1024;

         DatagramSocket socket = new DatagramSocket(discoveryProperties.bind.getPort(), discoveryProperties.bind.getAddress());
         DatagramPacket packet = new DatagramPacket(new byte[packetLength], 0, packetLength);

         socket.setSoTimeout(discoveryProperties.socketTimeout);

         for (int i = 0; (discoveryProperties.maxTries == -1) || (i < discoveryProperties.maxTries); i++)
         {
            try
            {
               socket.receive(packet);
            }
            catch (IOException exc)
            {
               exc.printStackTrace();
               break;
            }

            ByteArrayInputStream bais = new ByteArrayInputStream(packet.getData(), packet.getOffset(), packet.getLength());
            DataInputStream dis = new DataInputStream(bais);

            String theServiceName = dis.readUTF();
            if (!theServiceName.equals(discoveryProperties.serviceName))
               continue;

            String notifyHost = dis.readUTF();
            int notifyPort = dis.readInt();
            return new InetSocketAddress(notifyHost, notifyPort);
         }
      }
      catch (IOException exc)
      {
         exc.printStackTrace();
      }

      throw new NoSuchServiceException("Service \"" + discoveryProperties.serviceName + "\" not found");
   }

   public static class NoSuchServiceException extends RuntimeException
   {
      public NoSuchServiceException(String msg)
      {
         super(msg);
      }
   }
}