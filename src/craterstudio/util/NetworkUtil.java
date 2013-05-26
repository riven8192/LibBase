/*
 * Created on 27-jun-2006
 */

package craterstudio.util;

import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import craterstudio.io.Streams;
import craterstudio.text.Text;
import craterstudio.text.TextValues;

public class NetworkUtil
{

   /**
    * IP
    */

   public static final List<InetAddress> getPublicIPs()
   {
      List<InetAddress> results = new ArrayList<InetAddress>();

      List<InetAddress> ips = NetworkUtil.getIPs();

      for (InetAddress ip : ips)
      {
         if (ip.getHostAddress().equals("127.0.0.1"))
            continue;
         if (ip.getHostAddress().startsWith("10."))
            continue;
         if (ip.getHostAddress().startsWith("192.168."))
            continue;

         results.add(ip);
      }

      return results;
   }



   public static final List<InetAddress> getIPs()
   {
      List<NetworkInterface> nics = NetworkUtil.getNICs();
      List<InetAddress> results = new ArrayList<InetAddress>();

      for (NetworkInterface nic : nics)
      {
         Enumeration<InetAddress> addrs = nic.getInetAddresses();
         while (addrs.hasMoreElements())
         {
            InetAddress addr = addrs.nextElement();
            if (!addr.isLoopbackAddress())
               results.add(addr);
         }
      }

      return results;
   }



   public static final List<NetworkInterface> getNICs()
   {
      List<NetworkInterface> nics = new ArrayList<NetworkInterface>();
      Enumeration<NetworkInterface> nis;

      try
      {
         // may return null
         nis = NetworkInterface.getNetworkInterfaces();
      }
      catch (Exception exc)
      {
         nis = null;
      }

      if (nis == null)
         return nics;

      while (nis.hasMoreElements())
         nics.add(nis.nextElement());

      return nics;
   }



   public static final List<String> getMACs()
   {
      List<String> macs = new ArrayList<String>();

      try
      {
         int parts = 6;
         int splitters = parts - 1;
         int partLength = (parts * 2) + splitters;

         //
         String[] args;
         char splitter;
         String os = System.getProperty("os.name");

         if (os.contains("Windows"))
         {
            args = new String[] { "ipconfig", "/all" };
            splitter = '-';
         }
         else
         {
            args = new String[] { "ifconfig", "-a" };
            splitter = ':';
         }
         //

         Process p = Runtime.getRuntime().exec(args);
         byte[] stream = Streams.readProcess(p)[Streams.PROCESS_STDOUT];
         String output = Text.convert(stream);

         // traverse output
         for (int i = 0; i <= output.length() - partLength; i++)
         {
            String part = output.substring(i, i + partLength);

            if (Text.count(part, splitter) != splitters)
            {
               continue;
            }

            try
            {
               TextValues.parseInts(Text.split(part, splitter), 16);
            }
            catch (Exception exc)
            {
               continue;
            }

            macs.add(part);
         }
      }
      catch (Exception exc)
      {
         //
      }

      return macs;
   }



   public static List<InetAddress> getBroadcastAddresses()
   {
      List<InetAddress> list = new ArrayList<InetAddress>();
      try
      {
         for (NetworkInterface interf : IteratorUtil.foreach(NetworkInterface.getNetworkInterfaces()))
            for (InterfaceAddress interfAddr : interf.getInterfaceAddresses())
               list.add(interfAddr.getBroadcast());
      }
      catch (SocketException exc)
      {
         exc.printStackTrace();
      }
      return list;
   }



   public static List<InetAddress> getAddresses()
   {
      List<InetAddress> list = new ArrayList<InetAddress>();
      try
      {
         for (NetworkInterface interf : IteratorUtil.foreach(NetworkInterface.getNetworkInterfaces()))
            for (InterfaceAddress interfAddr : interf.getInterfaceAddresses())
               list.add(interfAddr.getAddress());
      }
      catch (SocketException exc)
      {
         exc.printStackTrace();
      }
      return list;
   }
}
