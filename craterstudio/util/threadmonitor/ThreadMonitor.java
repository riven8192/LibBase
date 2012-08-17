/*
 * Created on 10 jul 2008
 */

package craterstudio.util.threadmonitor;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;

public class ThreadMonitor
{
   private static ThreadMXBean tmxb;

   static
   {
      tmxb = ManagementFactory.getThreadMXBean();
      tmxb.setThreadCpuTimeEnabled(true);
   }

   //

   private long                tid;
   private CyclicUsageHistory  cpuTimeHistory;
   private CyclicUsageHistory  userTimeHistory;
   private CyclicUsageHistory  cpuUsageHistory;
   private CyclicUsageHistory  userUsageHistory;

   public ThreadMonitor(long tid, int slots)
   {
      this.tid = tid;
      this.cpuTimeHistory = new CyclicUsageHistory(slots);
      this.userTimeHistory = new CyclicUsageHistory(slots);
      this.cpuUsageHistory = new CyclicUsageHistory(slots);
      this.userUsageHistory = new CyclicUsageHistory(slots);
   }

   public long getId()
   {
      return tid;
   }

   private double totalCpuTime;
   private double totalUserTime;
   
   public double getTotalCpuTime()
   {
      return this.totalCpuTime;
   }
   
   public double getTotalUserTime()
   {
      return this.totalUserTime;
   }

   public void poll()
   {
      // a time of -1 means not alive

      double cpuTime = tmxb.getThreadCpuTime(this.tid) / 1000000000.0;
      this.totalCpuTime += cpuTime < 0 ? 0 : cpuTime;
      cpuTimeHistory.log(cpuTime < 0 ? 0 : cpuTime);
      cpuUsageHistory.log(cpuTimeHistory.previous(0) - cpuTimeHistory.previous(1));

      double userTime = tmxb.getThreadUserTime(this.tid) / 1000000000.0;
      this.totalUserTime += userTime < 0 ? 0 : userTime;
      userTimeHistory.log(userTime < 0 ? 0 : userTime);
      userUsageHistory.log(userTimeHistory.previous(0) - userTimeHistory.previous(1));
   }

   public CyclicUsageHistory getCpuTimeStats()
   {
      return this.cpuUsageHistory;
   }

   public CyclicUsageHistory getUserTimeStats()
   {
      return this.userUsageHistory;
   }
}