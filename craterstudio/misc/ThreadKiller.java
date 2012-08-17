/*
 * Created on Apr 17, 2012
 */

package craterstudio.misc;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadInfo;
import java.lang.management.ThreadMXBean;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import craterstudio.func.Callback;
import craterstudio.io.Logging;
import craterstudio.text.TextValues;
import craterstudio.util.HighLevel;

public class ThreadKiller {
   public static final Logger       LOG = Logging.init(ThreadKiller.class);
   
   public static final ThreadMXBean THREAD_BEAN;
   
   static {
      THREAD_BEAN = ManagementFactory.getThreadMXBean();
   }
   
   public static class ThreadStats {
      public final long id;
      
      public ThreadStats(long id) {
         this.id = id;
      }
      
      public double cpuUsage, userUsage;
      public double cpuTotal, userTotal;
   }
   
   public static void monitor(int seconds, Callback<ThreadStats> callback) {
      
      Map<Long, ThreadStats> threadIdToStats = new HashMap<Long, ThreadStats>();
      
      while (true) {
         HighLevel.sleep(seconds * 1000);
         
         long[] ids = THREAD_BEAN.getAllThreadIds();
         
         // cleanup
         {
            Set<Long> idSet = new HashSet<Long>();
            for (long id : ids) {
               idSet.add(Long.valueOf(id));
            }
            Set<Long> toRemove = new HashSet<Long>();
            for (Long gotId : threadIdToStats.keySet()) {
               if (!idSet.contains(gotId)) {
                  toRemove.add(gotId);
               }
            }
            for (Long id : toRemove) {
               threadIdToStats.remove(id);
            }
         }
         
         for (long id : ids) {
            
            ThreadStats stats = threadIdToStats.get(Long.valueOf(id));
            if (stats == null) {
               threadIdToStats.put(Long.valueOf(id), stats = new ThreadStats(id));
            }
            
            double cpuTotal = THREAD_BEAN.getThreadCpuTime(id) / 1000000000.0;
            double userTotal = THREAD_BEAN.getThreadUserTime(id) / 1000000000.0;
            
            stats.cpuUsage = (cpuTotal - stats.cpuTotal) / seconds;
            stats.userUsage = (userTotal - stats.userTotal) / seconds;
            
            stats.cpuTotal = cpuTotal;
            stats.userTotal = userTotal;
            
            callback.callback(stats);
         }
      }
   }
   
   public static String describeThread(long id) {
      ThreadInfo info = THREAD_BEAN.getThreadInfo(id);
      
      StringBuilder sb = new StringBuilder();
      sb.append("Thread id=").append(id);
      sb.append(", name=").append(info.getThreadName());
      return sb.toString();
   }
   
   public static String describeThreadPerf(long id) {
      
      double userTime = THREAD_BEAN.getThreadUserTime(id) / 1000000000.0;
      double cpuTime = THREAD_BEAN.getThreadCpuTime(id) / 1000000000.0;
      
      StringBuilder sb = new StringBuilder();
      sb.append(describeThread(id));
      sb.append(", cpu=").append(TextValues.formatNumber(cpuTime, 3)).append("s");
      sb.append(", user=").append(TextValues.formatNumber(userTime, 3)).append("s");
      return sb.toString();
   }
   
   @SuppressWarnings("deprecation")
   public static boolean killThread(long id) {
      Thread[] array = new Thread[32];
      while (true) {
         int got = Thread.enumerate(array);
         if (got < array.length) {
            break;
         }
         array = new Thread[array.length * 2];
      }
      
      for (Thread t : array) {
         if (t != null && t.getId() == id) {
            t.stop();
            return true;
         }
      }
      return false;
   }
   
   private static String dumpThreadInfo(long id) {
      ThreadInfo info = THREAD_BEAN.getThreadInfo(id);
      
      StringBuilder sb = new StringBuilder();
      sb.append(describeThreadPerf(id));
      sb.append("\r\n");
      for (StackTraceElement elem : info.getStackTrace()) {
         sb.append("\t").append(elem).append("\r\n");
      }
      sb.append("\r\n");
      return sb.toString();
   }
}
